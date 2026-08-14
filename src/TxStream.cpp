/*
 * Transmit path: packetisation, rate pacing and context emission.
 *
 * TODO: nothing other than this driver's own receiver has consumed the output
 * of this path. Both were written together and share one reading of the
 * standard, so an error common to both would not show up in a loopback test.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "SoapyVITA49.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <SoapySDR/Formats.hpp>
#include <SoapySDR/Logger.hpp>

namespace {

/* Bytes of VRT prologue on a transmitted data packet: header word, stream ID,
 * integer seconds and the 64-bit fractional timestamp. Class ID is not
 * emitted, so this is fixed. */
const size_t kTxPrologueBytes = 4 + 4 + 4 + 8;

long long monotonicNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

long long realtimeNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* A connected UDP socket reports the previous datagram's ICMP port-unreachable
 * as ECONNREFUSED on the next send, once per packet while the far end is not
 * listening. That is ordinary for a transmitter, so rate-limit it. */
void reportSendError(int err, long long nowNs, long long *nextReportNs,
                     const char *dest)
{
    if (nowNs < *nextReportNs)
        return;
    *nextReportNs = nowNs + 1000000000LL;

    if (err == ECONNREFUSED)
        SoapySDR::logf(SOAPY_SDR_WARNING,
            "vita49: nothing is listening on %s; transmitting anyway", dest);
    else
        SoapySDR::logf(SOAPY_SDR_WARNING, "vita49: send to %s failed: %s",
                       dest, strerror(err));
}

void sleepUntilMonotonic(long long deadlineNs)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(deadlineNs / 1000000000LL);
    ts.tv_nsec = (long)(deadlineNs % 1000000000LL);
    /* An absolute deadline avoids the drift a relative sleep accumulates over
     * thousands of packets per second. */
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr) == EINTR)
        ;
}

} /* anonymous namespace */

bool SoapyVITA49::openTxSockets(std::string &err)
{
    for (auto &c : _tx) {
        if (c->sock >= 0)
            continue;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            err = std::string("tx socket: ") + strerror(errno);
            return false;
        }

        int sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(c->destPort);
        if (inet_pton(AF_INET, c->destAddr.c_str(), &sa.sin_addr) != 1) {
            err = "tx: cannot parse address " + c->destAddr;
            close(fd);
            return false;
        }

        bool isMulticast = (ntohl(sa.sin_addr.s_addr) >= 0xE0000000u &&
                            ntohl(sa.sin_addr.s_addr) <  0xF0000000u);
        if (isMulticast) {
            /* Multicast needs an explicit hop limit; the default of one keeps
             * traffic on the local segment, which is rarely what is wanted for
             * a distribution stream. */
            int ttl = 8;
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        }

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            err = "tx connect " + c->destAddr + ": " + strerror(errno);
            close(fd);
            return false;
        }

        c->sock = fd;
        SoapySDR::logf(SOAPY_SDR_INFO, "vita49: transmitting to %s:%u sid %08x",
                       c->destAddr.c_str(), c->destPort, c->streamId);
    }
    return true;
}

void SoapyVITA49::closeTxSockets()
{
    _txRun = false;
    for (auto &c : _tx)
        if (c->queue) c->queue->wake();
    for (auto &t : _txThreads)
        if (t.joinable()) t.join();
    _txThreads.clear();

    for (auto &c : _tx) {
        if (c->sock >= 0) {
            close(c->sock);
            c->sock = -1;
        }
    }
}

/*
 * Emit an IF context packet describing the stream. A receiver that follows the
 * spec configures itself from this, which is what makes a transmitted stream
 * self-describing rather than something the far end has to be told about out
 * of band.
 */
void SoapyVITA49::sendContextPacket(size_t chIdx)
{
    if (chIdx >= _tx.size())
        return;
    TxChannel *c = _tx[chIdx].get();
    if (c->sock < 0)
        return;

    VRT::ContextInfo info;
    info.haveSampleRate = true;
    info.sampleRate     = c->sampleRate.load();
    info.haveRfFreq     = true;
    info.rfFreq         = c->centerFreq.load();
    info.haveFormat     = true;
    info.format         = c->wireFormat;
    info.linkEfficient  = (c->wireFormat == VRT::FMT_CI12);

    double bw = c->bandwidth.load();
    if (bw > 0.0) {
        info.haveBandwidth = true;
        info.bandwidth     = bw;
    }

    long long now = realtimeNs();
    std::vector<uint8_t> pkt = VRT::buildContext(
        c->streamId, c->ctxCount++, info,
        VRT::TSI_UTC, (uint32_t)(now / 1000000000LL),
        VRT::TSF_REALTIME_PS, (uint64_t)(now % 1000000000LL) * 1000ULL,
        c->hdrSwap);

    if (send(c->sock, pkt.data(), pkt.size(), 0) < 0 && errno != EAGAIN) {
        std::string dest = c->destAddr + ":" + std::to_string(c->destPort);
        reportSendError(errno, monotonicNs(), &c->nextSendReportNs, dest.c_str());
    }
}

/*
 * Transmit pacer. Packets leave on an absolute schedule derived from the
 * sample rate, because a UDP receiver has no flow control and a sender that
 * simply pushes as fast as it can will overrun it.
 */
void SoapyVITA49::transmitterLoop(size_t chIdx)
{
    if (chIdx >= _tx.size())
        return;
    TxChannel *c = _tx[chIdx].get();

    long long deadline = monotonicNs();
    long long nextContext = 0;
    bool wasStreaming = false;

    while (_txRun.load(std::memory_order_relaxed)) {
        long long now = monotonicNs();

        if (_emitTxContext && now >= nextContext) {
            sendContextPacket(chIdx);
            long long period = (long long)(_contextPeriodSec * 1e9);
            nextContext = now + (period > 0 ? period : 1000000000LL);
        }

        SampleBlock *b = c->queue->waitReady(50000);
        if (b == nullptr) {
            /* Nothing queued. If we were mid-burst the application failed to
             * keep up, which the host learns about through readStreamStatus. */
            if (wasStreaming) {
                c->underflows.fetch_add(1, std::memory_order_relaxed);
                wasStreaming = false;
            }
            deadline = monotonicNs();
            continue;
        }

        if (c->sock >= 0) {
            ssize_t n = send(c->sock, b->data.data(), b->bytes, 0);
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                std::string dest = c->destAddr + ":" + std::to_string(c->destPort);
                reportSendError(errno, now, &c->nextSendReportNs, dest.c_str());
            } else {
                c->packets.fetch_add(1, std::memory_order_relaxed);
            }
        }

        double rate = c->sampleRate.load();
        if (rate > 0.0 && b->samples > 0) {
            deadline += (long long)((double)b->samples / rate * 1e9);
            long long slack = deadline - monotonicNs();
            /* A schedule that has fallen far behind is reset rather than
             * chased, otherwise the sender bursts to catch up and makes the
             * overrun worse. */
            if (slack > 0)
                sleepUntilMonotonic(deadline);
            else if (slack < -100000000LL)
                deadline = monotonicNs();
        }

        c->queue->popReady();
        wasStreaming = true;
    }
}

int SoapyVITA49::writeStream(SoapySDR::Stream *stream, const void *const *buffs,
                             const size_t numElems, int &flags,
                             const long long timeNs, const long timeoutUs)
{
    StreamHandle *s = reinterpret_cast<StreamHandle *>(stream);
    if (s == nullptr || s->direction != SOAPY_SDR_TX)
        return SOAPY_SDR_STREAM_ERROR;
    if (_tx.empty())
        return SOAPY_SDR_STREAM_ERROR;

    const size_t hostBps = Convert::hostBytesPerSample(s->hostFormat);
    const bool haveTime  = (flags & SOAPY_SDR_HAS_TIME) != 0;

    size_t accepted = 0;

    for (size_t ci = 0; ci < s->channels.size(); ci++) {
        size_t chIdx = s->channels[ci];
        if (chIdx >= _tx.size())
            return SOAPY_SDR_STREAM_ERROR;
        TxChannel *c = _tx[chIdx].get();

        const VRT::SampleFormat wire = c->wireFormat;
        const size_t wireBps = VRT::bytesPerSample(wire);
        if (wireBps == 0)
            return SOAPY_SDR_STREAM_ERROR;

        /* Fit as many whole samples as the MTU allows once the prologue is
         * accounted for, then round down so the payload stays a whole number
         * of 32-bit words as the spec requires. */
        size_t payloadBudget = (c->mtu > kTxPrologueBytes)
                             ? c->mtu - kTxPrologueBytes : 0;
        if (payloadBudget < wireBps)
            return SOAPY_SDR_STREAM_ERROR;

        size_t perPacket = payloadBudget / wireBps;
        while (perPacket > 0 &&
               (Convert::payloadForSamples(perPacket, wire) & 3) != 0)
            perPacket--;
        if (perPacket == 0)
            return SOAPY_SDR_STREAM_ERROR;

        const uint8_t *src = (const uint8_t *)buffs[ci];
        size_t remaining = numElems;
        size_t done = 0;
        long long pktTime = haveTime ? timeNs : realtimeNs();
        double rate = c->sampleRate.load();

        while (remaining > 0) {
            size_t n = std::min(perPacket, remaining);

            /* Respect the caller's timeout instead of growing the queue
             * without bound: a full queue means the pacer is still working
             * through what was already handed over. */
            if (c->queue->readyCount() >= _rxBufferBlocks) {
                if (done > 0)
                    break;              /* partial write is a valid result */
                long waited = 0;
                const long step = 1000;
                while (c->queue->readyCount() >= _rxBufferBlocks &&
                       waited < timeoutUs) {
                    struct timespec ts = { 0, step * 1000 };
                    nanosleep(&ts, nullptr);
                    waited += step;
                }
                if (c->queue->readyCount() >= _rxBufferBlocks)
                    return SOAPY_SDR_TIMEOUT;
            }

            size_t payloadBytes = Convert::payloadForSamples(n, wire);
            size_t total = kTxPrologueBytes + payloadBytes;

            SampleBlock *b = c->queue->acquire(total);

            VRT::Builder builder(c->hdrSwap);
            builder.begin(VRT::PKT_SIGNAL_DATA, c->count++);
            builder.setStreamId(c->streamId);
            builder.setTimestamp(VRT::TSI_UTC,
                                 (uint32_t)(pktTime / 1000000000LL),
                                 VRT::TSF_REALTIME_PS,
                                 (uint64_t)(pktTime % 1000000000LL) * 1000ULL);

            /* Convert straight into the packet buffer, then let the builder
             * patch the size field once the payload length is known. */
            std::vector<uint8_t> &raw = builder.raw();
            size_t payloadOffset = raw.size();
            raw.resize(payloadOffset + payloadBytes);
            Convert::hostToWire(src + done * hostBps, s->hostFormat,
                                raw.data() + payloadOffset, wire, c->dataSwap, n,
                                c->iqSwap);

            const std::vector<uint8_t> &pkt = builder.finish();
            memcpy(b->data.data(), pkt.data(), pkt.size());
            b->bytes   = pkt.size();
            b->samples = n;

            c->queue->publish(b);

            done      += n;
            remaining -= n;
            if (rate > 0.0)
                pktTime += (long long)((double)n / rate * 1e9);
        }

        /* Every channel is written the same number of elements, so the first
         * channel sets the answer and the rest must match it. */
        if (ci == 0)
            accepted = done;
        else
            accepted = std::min(accepted, done);
    }

    if (accepted == 0)
        return SOAPY_SDR_TIMEOUT;

    flags = 0;
    return (int)accepted;
}
