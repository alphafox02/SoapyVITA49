/*
 * Receive path: UDP endpoints, stream demultiplexing and readStream.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "SoapyVITA49.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <SoapySDR/Formats.hpp>
#include <SoapySDR/Logger.hpp>

/* ------------------------------------------------------------------ */
/* BlockQueue                                                         */
/* ------------------------------------------------------------------ */

BlockQueue::~BlockQueue()
{
    for (auto *b : _ready) delete b;
    for (auto *b : _free)  delete b;
}

SampleBlock *BlockQueue::acquire(size_t capacity)
{
    std::lock_guard<std::mutex> lk(_mtx);
    SampleBlock *b;
    if (!_free.empty()) {
        b = _free.back();
        _free.pop_back();
    } else {
        b = new SampleBlock();
    }
    if (b->data.size() < capacity)
        b->data.resize(capacity);
    b->bytes  = 0;
    b->offset = 0;
    b->flags  = 0;
    b->hasTime = false;
    return b;
}

void BlockQueue::publish(SampleBlock *b)
{
    std::unique_lock<std::mutex> lk(_mtx);
    /* A UDP source will not slow down for us, so a backlog costs the oldest
     * data rather than unbounded memory. The drop is counted and surfaces as
     * an overflow to the host. */
    while (_ready.size() >= _max) {
        SampleBlock *old = _ready.front();
        _ready.pop_front();
        _free.push_back(old);
        _dropped.fetch_add(1, std::memory_order_relaxed);
    }
    _ready.push_back(b);
    lk.unlock();
    _cv.notify_one();
}

SampleBlock *BlockQueue::waitReady(long timeoutUs)
{
    std::unique_lock<std::mutex> lk(_mtx);
    if (_ready.empty()) {
        if (timeoutUs <= 0)
            return nullptr;
        _cv.wait_for(lk, std::chrono::microseconds(timeoutUs),
                     [this] { return !_ready.empty(); });
    }
    return _ready.empty() ? nullptr : _ready.front();
}

SampleBlock *BlockQueue::peekReady()
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _ready.empty() ? nullptr : _ready.front();
}

void BlockQueue::popReady()
{
    std::lock_guard<std::mutex> lk(_mtx);
    if (!_ready.empty()) {
        _free.push_back(_ready.front());
        _ready.pop_front();
    }
}

void BlockQueue::release(SampleBlock *b)
{
    std::lock_guard<std::mutex> lk(_mtx);
    _free.push_back(b);
}

void BlockQueue::flush()
{
    std::lock_guard<std::mutex> lk(_mtx);
    while (!_ready.empty()) {
        _free.push_back(_ready.front());
        _ready.pop_front();
    }
}

void BlockQueue::wake() { _cv.notify_all(); }

size_t BlockQueue::readyCount()
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _ready.size();
}

/* ------------------------------------------------------------------ */
/* Endpoints                                                          */
/* ------------------------------------------------------------------ */

namespace {

/* Convert a VRT timestamp to nanoseconds since the epoch. Sources that count
 * samples rather than picoseconds need the sample rate to place the fraction,
 * so a zero rate degrades to whole-second resolution rather than nonsense. */
long long vrtTimeNs(VRT::TSI tsi, uint32_t tsInt, VRT::TSF tsf, uint64_t tsFrac,
                    double sampleRate)
{
    long long ns = 0;

    switch (tsi) {
    case VRT::TSI_UTC:
        ns = (long long)tsInt * 1000000000LL;
        break;
    case VRT::TSI_GPS:
        /* GPS epoch is 1980-01-06, 315964800 s after the Unix epoch, and GPS
         * time does not observe leap seconds. The offset is applied without a
         * leap-second correction because VRT carries no leap count. */
        ns = ((long long)tsInt + 315964800LL) * 1000000000LL;
        break;
    default:
        ns = 0;
        break;
    }

    switch (tsf) {
    case VRT::TSF_REALTIME_PS:
        ns += (long long)(tsFrac / 1000ULL);
        break;
    case VRT::TSF_SAMPLE_COUNT:
        if (sampleRate > 0.0)
            ns += (long long)((double)tsFrac / sampleRate * 1e9);
        break;
    default:
        break;
    }

    return ns;
}

long long hostNowNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * Sample-to-sample correlation of a 16-bit payload read one way and the other.
 *
 * Sample byte order cannot be read off the packet, so it is inherited from the
 * header and can be wrong. It is measurable, though: a band-limited signal is
 * correlated from one sample to the next, while the same bytes read in the
 * wrong order are effectively random and correlate at nothing.
 *
 * The payload interleaves I and Q, and for a complex signal those are in
 * quadrature and correlate at nothing however the bytes are read. The stride
 * is therefore two items, which compares each component with the previous
 * value of the same component. Returns the correlation in [-1, 1].
 */
double sampleCorrelation(const uint8_t *p, size_t nItems, bool swap)
{
    if (nItems < 64)
        return 0.0;

    double sum = 0.0, sumSq = 0.0, sumProd = 0.0;
    size_t pairs = 0;

    for (size_t i = 0; i < nItems; i++) {
        uint16_t raw = swap ? (uint16_t)((uint16_t)p[i * 2 + 1] << 8 | p[i * 2])
                            : (uint16_t)((uint16_t)p[i * 2] << 8 | p[i * 2 + 1]);
        double v = (double)(int16_t)raw;
        sum   += v;
        sumSq += v * v;

        if (i >= 2) {
            uint16_t praw = swap
                ? (uint16_t)((uint16_t)p[(i - 2) * 2 + 1] << 8 | p[(i - 2) * 2])
                : (uint16_t)((uint16_t)p[(i - 2) * 2] << 8 | p[(i - 2) * 2 + 1]);
            sumProd += v * (double)(int16_t)praw;
            pairs++;
        }
    }

    if (pairs == 0)
        return 0.0;

    const double n    = (double)nItems;
    const double mean = sum / n;
    const double var  = sumSq / n - mean * mean;
    if (var < 1.0)
        return 0.0;   /* silence or a constant tells us nothing */

    return (sumProd / (double)pairs - mean * mean) / var;
}

/* TODO: IPv4 only. The capture scan classifies IPv6 streams, so they appear in
 * a scan and then cannot be opened. */
int openRxSocket(const std::string &addr, uint16_t port, int rcvbuf,
                 bool allowReuse, std::string &err)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        err = std::string("socket: ") + strerror(errno);
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /*
     * Report a clamped buffer rather than leaving it to be discovered as
     * unexplained packet loss. Linux reports twice what it granted, so the
     * effective size is half of what getsockopt returns; comparing the raw
     * value against the request misses any clamp above half the request.
     */
    int actual = 0;
    socklen_t alen = sizeof(actual);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &alen) == 0) {
#ifdef __linux__
        const int granted = actual / 2;
#else
        const int granted = actual;
#endif
        if (granted < rcvbuf)
            SoapySDR::logf(SOAPY_SDR_WARNING,
                "vita49: socket receive buffer is %d bytes, asked for %d; raise "
                "it with sysctl -w net.core.rmem_max=%d", granted, rcvbuf, rcvbuf);
    }

    struct in_addr target;
    bool haveAddr = (inet_pton(AF_INET, addr.c_str(), &target) == 1);
    bool isMulticast = haveAddr &&
                       (ntohl(target.s_addr) >= 0xE0000000u &&
                        ntohl(target.s_addr) <  0xF0000000u);

    /* Multicast is shared, so SO_REUSEADDR lets several applications join one
     * group. Unicast is not: with the option set a second process binds the
     * same port and then quietly takes most of the traffic, leaving the first
     * with a fraction of the stream and no error to show for it. Withholding
     * it turns that into an honest EADDRINUSE. */
    if (isMulticast || allowReuse) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    /* A multicast group is joined, not bound to. Binding the wildcard and
     * joining the group is what actually delivers the traffic. */
    sa.sin_addr.s_addr = (haveAddr && !isMulticast) ? target.s_addr
                                                    : htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errno == EADDRINUSE && !isMulticast) {
            err = "UDP port " + std::to_string(port) + " is already in use. "
                  "A unicast stream can only be received by one process at a "
                  "time, and a second receiver would silently take the traffic "
                  "from the first. Close the other application, or have the "
                  "source send to a multicast group, which any number of "
                  "receivers can share.";
        } else {
            err = "bind " + addr + ":" + std::to_string(port) + ": " +
                  strerror(errno);
        }
        close(fd);
        return -1;
    }

    if (isMulticast) {
        struct ip_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.imr_multiaddr = target;
        mr.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
            err = "join " + addr + ": " + strerror(errno);
            close(fd);
            return -1;
        }
    }

    return fd;
}

} /* anonymous namespace */

bool SoapyVITA49::openEndpoints(std::string &err)
{
    if (!_endpoints.empty())
        return true;

    /* Channels sharing a port must share one socket, because a port carrying
     * several stream IDs can only be bound once. */
    for (size_t i = 0; i < _rx.size(); i++) {
        RxEndpoint *found = nullptr;
        for (auto &ep : _endpoints) {
            if (ep->port == _rx[i]->port && ep->bindAddr == _rx[i]->bindAddr) {
                found = ep.get();
                break;
            }
        }
        if (found == nullptr) {
            std::unique_ptr<RxEndpoint> ep(new RxEndpoint());
            ep->bindAddr = _rx[i]->bindAddr;
            ep->port     = _rx[i]->port;
            _endpoints.push_back(std::move(ep));
            found = _endpoints.back().get();
        }
        found->channels.push_back(i);
    }

    for (auto &ep : _endpoints) {
        ep->sock = openRxSocket(ep->bindAddr, ep->port, _socketRcvBuf,
                                _allowPortReuse, err);
        if (ep->sock < 0) {
            closeEndpoints();
            return false;
        }
        SoapySDR::logf(SOAPY_SDR_INFO, "vita49: listening on %s:%u for %zu stream(s)",
                       ep->bindAddr.c_str(), ep->port, ep->channels.size());
    }

    return true;
}

void SoapyVITA49::closeEndpoints()
{
    for (auto &ep : _endpoints) {
        ep->run = false;
        if (ep->thread.joinable())
            ep->thread.join();
        if (ep->sock >= 0) {
            close(ep->sock);
            ep->sock = -1;
        }
    }
    _endpoints.clear();
}

RxChannel *SoapyVITA49::rxChannelForStream(RxEndpoint *ep, uint32_t sid,
                                           bool hasSid)
{
    RxChannel *wildcard = nullptr;

    for (size_t idx : ep->channels) {
        RxChannel *c = _rx[idx].get();
        if (c->anyStreamId) {
            if (wildcard == nullptr)
                wildcard = c;
            continue;
        }
        if (hasSid && c->streamId == sid)
            return c;
    }

    /* A packet with no stream ID, or one nobody claimed, goes to a channel
     * configured to take anything. */
    return wildcard;
}

void SoapyVITA49::handleRxPacket(RxEndpoint *ep, const uint8_t *pkt, size_t len)
{
    /* Header byte order is a per-endpoint property, so any channel's setting
     * describes the whole socket. */
    RxChannel *first = _rx[ep->channels.front()].get();
    const bool hdrSwap = first->hdrSwap;

    size_t vrtLen = 0;
    size_t off = VRT::vrlStrip(pkt, len, &vrtLen);
    if (vrtLen < 4)
        return;

    const uint8_t *vrt = pkt + off;

    VRT::Header h;
    if (!VRT::parseHeader(vrt, vrtLen, hdrSwap, &h))
        return;

    if (h.type == VRT::PKT_IF_CONTEXT || h.type == VRT::PKT_EXT_CONTEXT) {
        VRT::ContextInfo ci;
        if (!VRT::parseContext(vrt, vrtLen, hdrSwap, &ci))
            return;

        RxChannel *c = rxChannelForStream(ep, ci.streamId, true);
        if (c == nullptr)
            return;

        if (ci.haveSampleRate && ci.sampleRate > 0.0) {
            double prev = c->sampleRate.exchange(ci.sampleRate);
            if (prev != ci.sampleRate)
                SoapySDR::logf(SOAPY_SDR_INFO, "vita49: sample rate %.0f Hz",
                               ci.sampleRate);
        }
        if (ci.haveRfFreq) {
            double prev = c->centerFreq.exchange(ci.rfFreq);
            if (prev != ci.rfFreq)
                SoapySDR::logf(SOAPY_SDR_INFO, "vita49: RF frequency %.0f Hz",
                               ci.rfFreq);
        }
        if (ci.haveBandwidth) c->bandwidth = ci.bandwidth;
        if (ci.haveGain)      c->gain      = ci.gainStage1 + ci.gainStage2;
        if (ci.haveAgcMode)   c->agcMode   = ci.agcAuto ? 1 : 0;
        if (ci.haveRefLevel)  c->refLevel  = ci.refLevel;
        if (ci.haveOverRange) c->overRange = ci.overRange;

        /* An explicit format= argument wins, because a source that mislabels
         * its own payload is exactly when the override is needed. */
        if (ci.haveFormat && !c->wireFormatLocked && ci.format != c->wireFormat) {
            SoapySDR::logf(SOAPY_SDR_INFO, "vita49: payload format %s",
                           VRT::formatName(ci.format));
            c->wireFormat = ci.format;
        }
        return;
    }

    if (h.type != VRT::PKT_SIGNAL_DATA && h.type != VRT::PKT_SIGNAL_DATA_NO_SID)
        return;

    RxChannel *c = rxChannelForStream(ep, h.streamId, h.hasStreamId);
    if (c == nullptr || c->queue == nullptr)
        return;

    int flags = 0;

    /* The four-bit counter only detects loss up to fifteen missing packets,
     * which is all VRT offers; anything larger is indistinguishable. */
    if (c->haveCount) {
        uint8_t expected = (uint8_t)((c->lastCount + 1) & 0xF);
        if (h.count != expected) {
            c->gaps.fetch_add(1, std::memory_order_relaxed);
            flags |= SOAPY_SDR_END_ABRUPT;
        }
    }
    c->lastCount = h.count;
    c->haveCount = true;
    c->packets.fetch_add(1, std::memory_order_relaxed);

    /*
     * The trailer reports what the source thinks of its own data. Sample loss
     * is authoritative in a way the packet counter is not: the counter only
     * shows datagrams missing between here and there, while the source sets
     * this bit when it dropped samples before they ever left.
     */
    if (h.hasTrailer) {
        VRT::Trailer tr;
        if (VRT::parseTrailer(vrt, h, hdrSwap, &tr)) {
            if (tr.haveSampleLoss && tr.sampleLoss) {
                c->gaps.fetch_add(1, std::memory_order_relaxed);
                flags |= SOAPY_SDR_END_ABRUPT;
            }
            if (tr.haveOverRange && tr.overRange)
                c->overRange.fetch_add(1, std::memory_order_relaxed);
            /* Data the source has marked invalid is still delivered, because
             * discarding it silently would leave a hole the application cannot
             * see; the flag is what tells it. */
            if (tr.haveValidData && !tr.validData)
                flags |= SOAPY_SDR_END_ABRUPT;
        }
    }

    if (h.payloadBytes == 0 || h.payloadOffset + h.payloadBytes > vrtLen)
        return;

    const VRT::SampleFormat wire = c->wireFormat;
    size_t nSamples = Convert::samplesInPayload(h.payloadBytes, wire);
    if (nSamples == 0)
        return;

    /*
     * Cross-check the sample byte order once. Only a decisive result is
     * reported and nothing is changed automatically: switching on a heuristic
     * would corrupt every sample when the heuristic is wrong, whereas a
     * warning costs one log line.
     */
    if (!c->endianChecked && wire == VRT::FMT_CI16 && nSamples >= 256) {
        c->endianChecked = true;
        const uint8_t *pay = vrt + h.payloadOffset;
        double asIs  = sampleCorrelation(pay, nSamples * 2, c->dataSwap);
        double other = sampleCorrelation(pay, nSamples * 2, !c->dataSwap);
        if (other > 0.30 && asIs < 0.05)
            SoapySDR::logf(SOAPY_SDR_WARNING,
                "vita49: samples look byte-swapped (correlation %.2f as read, "
                "%.2f reversed); try data_endian=%s",
                asIs, other, c->dataSwap ? "big" : "little");
    }

    size_t outBytes = nSamples * Convert::hostBytesPerSample(_rxHostFormat);
    SampleBlock *b = c->queue->acquire(outBytes);

    Convert::wireToHost(vrt + h.payloadOffset, wire, c->dataSwap,
                        b->data.data(), _rxHostFormat, nSamples, c->iqSwap);
    b->bytes = outBytes;
    b->flags = flags;

    if (h.tsi != VRT::TSI_NONE || h.tsf != VRT::TSF_NONE) {
        long long t = vrtTimeNs(h.tsi, h.tsInt, h.tsf, h.tsFrac,
                                c->sampleRate.load());

        if (_timeUseHost) {
            t = hostNowNs();
        } else if (_timeAuto && !_timeMeasured.load(std::memory_order_acquire)) {
            /* A source whose clock was never set is wrong by a large constant.
             * Measuring it once keeps the stream's own precision, which is far
             * better than the arrival time, while fixing the epoch. */
            long long off = hostNowNs() - t;
            _timeOffsetNs.store(off, std::memory_order_relaxed);
            _timeMeasured.store(true, std::memory_order_release);
            SoapySDR::logf(SOAPY_SDR_INFO,
                "vita49: source clock is %.3f s from this host, correcting "
                "timestamps by that amount", (double)off / 1e9);
        }

        b->timeNs = t + _timeOffsetNs.load(std::memory_order_relaxed);
        b->hasTime = true;
        c->lastTimeNs.store(b->timeNs, std::memory_order_relaxed);
    } else if (_timeUseHost) {
        b->timeNs  = hostNowNs();
        b->hasTime = true;
        c->lastTimeNs.store(b->timeNs, std::memory_order_relaxed);
    }

    c->queue->publish(b);
}

void SoapyVITA49::receiverLoop(RxEndpoint *ep)
{
#ifdef __linux__
    /* One syscall per datagram is the limit long before the wire is: 10 GbE in
     * jumbo frames is over 100k datagrams a second. Slots are sized for a
     * jumbo frame rather than the 64 KiB a datagram may reach, since a batch of
     * maximum-size slots would be 4 MiB per endpoint. */
    const size_t kBatch = 64;
    const size_t kSlot  = 16384;

    std::vector<uint8_t>        pool(kBatch * kSlot);
    std::vector<struct mmsghdr> msgs(kBatch);
    std::vector<struct iovec>   iov(kBatch);

    for (size_t i = 0; i < kBatch; i++) {
        iov[i].iov_base = pool.data() + i * kSlot;
        iov[i].iov_len  = kSlot;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov    = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    bool warnedTruncation = false;

    while (ep->run.load(std::memory_order_relaxed)) {
        struct pollfd pfd;
        pfd.fd     = ep->sock;
        pfd.events = POLLIN;

        /* A bounded wait keeps the stop flag responsive without a busy loop. */
        if (poll(&pfd, 1, 200) <= 0)
            continue;

        for (;;) {
            int n = recvmmsg(ep->sock, msgs.data(), (unsigned)kBatch,
                             MSG_DONTWAIT, nullptr);
            if (n <= 0)
                break;

            for (int i = 0; i < n; i++) {
                if (msgs[i].msg_hdr.msg_flags & MSG_TRUNC) {
                    if (!warnedTruncation) {
                        warnedTruncation = true;
                        /* The reported length is what fitted, not what was
                         * sent, so the true size is unknown here. */
                        SoapySDR::logf(SOAPY_SDR_ERROR,
                            "vita49: a datagram larger than the %zu byte receive "
                            "slot arrived and was dropped; this build cannot "
                            "carry VRT packets that large", kSlot);
                    }
                    continue;
                }
                handleRxPacket(ep, (const uint8_t *)iov[i].iov_base,
                               (size_t)msgs[i].msg_len);
            }

            /* A short batch means the socket is drained; go back to polling
             * rather than spinning on empty reads. */
            if ((size_t)n < kBatch)
                break;
        }
    }
#else
    std::vector<uint8_t> buf(65536);

    while (ep->run.load(std::memory_order_relaxed)) {
        struct pollfd pfd;
        pfd.fd     = ep->sock;
        pfd.events = POLLIN;

        if (poll(&pfd, 1, 200) <= 0)
            continue;

        for (;;) {
            ssize_t n = recv(ep->sock, buf.data(), buf.size(), MSG_DONTWAIT);
            if (n <= 0)
                break;
            handleRxPacket(ep, buf.data(), (size_t)n);
        }
    }
#endif
}

/* ------------------------------------------------------------------ */
/* Stream API                                                         */
/* ------------------------------------------------------------------ */

std::vector<std::string> SoapyVITA49::getStreamFormats(const int,
                                                       const size_t) const
{
    return { SOAPY_SDR_CF32, SOAPY_SDR_CS16, SOAPY_SDR_CS8 };
}

std::string SoapyVITA49::getNativeStreamFormat(const int direction,
                                               const size_t channel,
                                               double &fullScale) const
{
    /* The native format is whatever the wire carries, so a host that asks can
     * pick the conversion-free path. */
    VRT::SampleFormat wire = VRT::FMT_CI16;
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        wire = _rx[channel]->wireFormat;
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        wire = _tx[channel]->wireFormat;

    switch (wire) {
    case VRT::FMT_CF32: fullScale = 1.0;     return SOAPY_SDR_CF32;
    case VRT::FMT_CI8:  fullScale = 128.0;   return SOAPY_SDR_CS8;
    case VRT::FMT_CI12: fullScale = 2048.0;  return SOAPY_SDR_CS16;
    default:            fullScale = 32768.0; return SOAPY_SDR_CS16;
    }
}

SoapySDR::ArgInfoList SoapyVITA49::getStreamArgsInfo(const int,
                                                     const size_t) const
{
    return SoapySDR::ArgInfoList();
}

SoapySDR::Stream *SoapyVITA49::setupStream(const int direction,
                                           const std::string &format,
                                           const std::vector<size_t> &channels,
                                           const SoapySDR::Kwargs &)
{
    Convert::HostFormat host;
    if (!Convert::hostFormatFromString(format, &host))
        throw std::runtime_error("vita49: unsupported stream format " + format);

    std::unique_ptr<StreamHandle> s(new StreamHandle());
    s->direction  = direction;
    s->hostFormat = host;
    s->channels   = channels;
    if (s->channels.empty())
        s->channels.push_back(0);

    const size_t avail = getNumChannels(direction);
    for (size_t ch : s->channels) {
        if (ch >= avail)
            throw std::runtime_error("vita49: channel " + std::to_string(ch) +
                                     " does not exist");
    }

    if (direction == SOAPY_SDR_RX) {
        _rxHostFormat = host;
        std::string err;
        /* Bind now rather than at activate so a port conflict is reported
         * where the host can still act on it. */
        if (!openEndpoints(err))
            throw std::runtime_error("vita49: " + err);
    } else {
        _txHostFormat = host;
        std::string err;
        if (!openTxSockets(err))
            throw std::runtime_error("vita49: " + err);
    }

    return reinterpret_cast<SoapySDR::Stream *>(s.release());
}

void SoapyVITA49::closeStream(SoapySDR::Stream *stream)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr)
        return;
    if (s->active)
        deactivateStream(stream, 0, 0);
    if (s->direction == SOAPY_SDR_RX)
        closeEndpoints();
    else
        closeTxSockets();
    delete s;
}

size_t SoapyVITA49::getStreamMTU(SoapySDR::Stream *stream) const
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    /* One VRT packet is the natural transfer unit; a jumbo frame of 16-bit
     * complex samples holds about two thousand. */
    return (s != nullptr) ? s->mtuSamples : 4096;
}

int SoapyVITA49::activateStream(SoapySDR::Stream *stream, const int flags,
                                const long long, const size_t)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr)
        return SOAPY_SDR_STREAM_ERROR;
    if (flags != 0)
        return SOAPY_SDR_NOT_SUPPORTED;

    if (s->direction == SOAPY_SDR_RX) {
        for (auto &c : _rx) {
            if (c->queue) {
                c->queue->flush();
                c->queue->clearDropped();
            }
            c->haveCount = false;
        }
        for (auto &ep : _endpoints) {
            if (ep->run.exchange(true))
                continue;
            RxEndpoint *raw = ep.get();
            ep->thread = std::thread([this, raw] { this->receiverLoop(raw); });
        }
    } else {
        if (!_txRun.exchange(true)) {
            for (size_t i = 0; i < _tx.size(); i++)
                _txThreads.emplace_back([this, i] { this->transmitterLoop(i); });
        }
    }

    s->active = true;
    return 0;
}

int SoapyVITA49::deactivateStream(SoapySDR::Stream *stream, const int flags,
                                  const long long)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr)
        return SOAPY_SDR_STREAM_ERROR;
    if (flags != 0)
        return SOAPY_SDR_NOT_SUPPORTED;

    if (s->direction == SOAPY_SDR_RX) {
        for (auto &ep : _endpoints) {
            ep->run = false;
            if (ep->thread.joinable())
                ep->thread.join();
        }
        for (auto &c : _rx)
            if (c->queue) c->queue->flush();
    } else {
        _txRun = false;
        for (auto &c : _tx)
            if (c->queue) c->queue->wake();
        for (auto &t : _txThreads)
            if (t.joinable()) t.join();
        _txThreads.clear();
    }

    s->active = false;
    return 0;
}

int SoapyVITA49::readStream(SoapySDR::Stream *stream, void *const *buffs,
                            const size_t numElems, int &flags,
                            long long &timeNs, const long timeoutUs)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr || s->direction != SOAPY_SDR_RX)
        return SOAPY_SDR_STREAM_ERROR;

    flags  = 0;
    timeNs = 0;

    const size_t bps = Convert::hostBytesPerSample(s->hostFormat);
    const size_t nch = s->channels.size();

    /* All channels must return the same count, so the transfer is limited by
     * whichever has least ready. */
    std::vector<SampleBlock *> heads(nch, nullptr);

    /* Each channel waits on what is left of the caller's timeout. Returning
     * the moment a later channel happens to be empty would hand back a
     * timeout while data was still arriving, and a host that retries
     * immediately would spin instead of blocking. */
    const std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::microseconds(timeoutUs);

    for (size_t i = 0; i < nch; i++) {
        RxChannel *c = _rx[s->channels[i]].get();
        if (c->queue == nullptr)
            return SOAPY_SDR_STREAM_ERROR;

        long remaining = timeoutUs;
        if (i > 0) {
            remaining = (long)std::chrono::duration_cast<std::chrono::microseconds>(
                            deadline - std::chrono::steady_clock::now()).count();
            if (remaining < 0)
                remaining = 0;
        }

        heads[i] = c->queue->waitReady(remaining);
        if (heads[i] == nullptr)
            return SOAPY_SDR_TIMEOUT;
    }

    size_t n = numElems;
    for (size_t i = 0; i < nch; i++) {
        size_t avail = (heads[i]->bytes - heads[i]->offset) / bps;
        n = std::min(n, avail);
    }
    if (n == 0)
        return SOAPY_SDR_TIMEOUT;

    for (size_t i = 0; i < nch; i++) {
        SampleBlock *b = heads[i];
        memcpy(buffs[i], b->data.data() + b->offset, n * bps);

        if (i == 0) {
            if (b->hasTime) {
                /* Advance the reported time by whatever was already consumed
                 * from this packet so a partial read still lands correctly. */
                RxChannel *c = _rx[s->channels[0]].get();
                double rate = c->sampleRate.load();
                long long consumed = (long long)(b->offset / bps);
                timeNs = b->timeNs;
                if (rate > 0.0 && consumed > 0)
                    timeNs += (long long)((double)consumed / rate * 1e9);
                flags |= SOAPY_SDR_HAS_TIME;
            }
            if (b->offset == 0)
                flags |= b->flags;   /* gap markers belong to the packet start */
        }

        b->offset += n * bps;
        if (b->offset >= b->bytes) {
            RxChannel *c = _rx[s->channels[i]].get();
            c->queue->popReady();
        }
    }

    return (int)n;
}

int SoapyVITA49::readStreamStatus(SoapySDR::Stream *stream, size_t &chanMask,
                                  int &flags, long long &timeNs,
                                  const long timeoutUs)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr)
        return SOAPY_SDR_STREAM_ERROR;

    chanMask = 0;
    flags    = 0;
    timeNs   = 0;

    if (s->direction == SOAPY_SDR_RX) {
        for (size_t i = 0; i < s->channels.size(); i++) {
            RxChannel *c = _rx[s->channels[i]].get();
            if (c->queue && c->queue->dropped() > 0) {
                c->queue->clearDropped();
                chanMask |= (size_t)1 << i;
            }
        }
        if (chanMask != 0)
            return SOAPY_SDR_OVERFLOW;
    } else {
        for (size_t i = 0; i < s->channels.size(); i++) {
            TxChannel *c = _tx[s->channels[i]].get();
            if (c->underflows.exchange(0) > 0)
                chanMask |= (size_t)1 << i;
        }
        if (chanMask != 0)
            return SOAPY_SDR_UNDERFLOW;
    }

    /* Nothing to report: honour the timeout so a status thread does not spin. */
    if (timeoutUs > 0) {
        struct timespec ts;
        ts.tv_sec  = timeoutUs / 1000000;
        ts.tv_nsec = (timeoutUs % 1000000) * 1000;
        nanosleep(&ts, nullptr);
    }
    return SOAPY_SDR_TIMEOUT;
}
