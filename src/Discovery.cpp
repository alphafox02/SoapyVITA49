/*
 * Discovery of VITA 49 streams on the network.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Discovery.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#else
#include <poll.h>
#endif

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

namespace Discovery {

/* Ports tried first by a quick scan. A full scan covers the whole range
 * regardless; this only sets the order. */
const uint16_t kWellKnownPorts[] = {
    4660, 4661, 4662, 4663, 4664, 4665, 4666, 4667,
    4991, 4992, 4993, 4994, 5000, 5001, 5002, 5004,
    8880, 9090, 9091, 10000, 10001, 30000, 50000,
};
const size_t kWellKnownPortCount = sizeof(kWellKnownPorts) / sizeof(kWellKnownPorts[0]);

static int64_t nowUnix()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec;
}

static int64_t nowMs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

std::string StreamInfo::key() const
{
    char buf[96];
    snprintf(buf, sizeof(buf), "%s:%u/%08x", dstAddr.c_str(), dstPort, streamId);
    return std::string(buf);
}

std::string StreamInfo::label() const
{
    char buf[256];
    char freqStr[48] = "";
    char rateStr[48] = "";

    if (rfFreq > 0.0)
        snprintf(freqStr, sizeof(freqStr), " %.3f MHz", rfFreq / 1e6);
    if (sampleRate > 0.0)
        snprintf(rateStr, sizeof(rateStr), " %.4g Msps", sampleRate / 1e6);
    else if (observedRate > 0.0)
        snprintf(rateStr, sizeof(rateStr), " ~%.4g Msps", observedRate / 1e6);

    /* Only say something about liveness when it was actually checked, so a
     * plain scan result is not decorated with a claim it cannot support. */
    const char *state = "";
    if      (liveness == LIVE_IDLE) state = " [not streaming]";
    else if (liveness == LIVE_BUSY) state = " [in use by another app]";

    if (hasStreamId)
        snprintf(buf, sizeof(buf), "VITA-49 %s:%u sid %08x%s%s%s",
                 dstAddr.c_str(), dstPort, streamId, freqStr, rateStr, state);
    else
        snprintf(buf, sizeof(buf), "VITA-49 %s:%u%s%s%s",
                 dstAddr.c_str(), dstPort, freqStr, rateStr, state);

    return std::string(buf);
}

/* ------------------------------------------------------------------ */
/* Classification                                                     */
/* ------------------------------------------------------------------ */

void classify(std::vector<StreamInfo> &table,
              const std::string &srcAddr, const std::string &dstAddr,
              uint16_t dstPort, const uint8_t *pkt, size_t len)
{
    bool swap = false;
    if (!VRT::looksLikeVRT(pkt, len, &swap))
        return;

    size_t vrtLen = 0;
    size_t off = VRT::vrlStrip(pkt, len, &vrtLen);

    VRT::Header h;
    if (!VRT::parseHeader(pkt + off, vrtLen, swap, &h))
        return;

    StreamInfo *rec = nullptr;
    for (auto &s : table) {
        if (s.dstPort == dstPort && s.dstAddr == dstAddr &&
            s.streamId == h.streamId && s.hasStreamId == h.hasStreamId) {
            rec = &s;
            break;
        }
    }
    if (rec == nullptr) {
        StreamInfo s;
        s.srcAddr     = srcAddr;
        s.dstAddr     = dstAddr;
        s.dstPort     = dstPort;
        s.streamId    = h.streamId;
        s.hasStreamId = h.hasStreamId;
        s.hdrSwap     = swap;
        s.dataSwap    = swap;   /* assumed to match; override with data_endian */
        s.vrlFramed   = (off != 0);
        s.seqRun      = 0;
        table.push_back(s);
        rec = &table.back();
        /* Seed the sequence tracker so the first packet does not count as a
         * match; runs are only credited from the second packet onward. */
        rec->lastSeen = 0;
    }

    rec->lastSeen = nowUnix();

    if (h.type == VRT::PKT_IF_CONTEXT || h.type == VRT::PKT_EXT_CONTEXT) {
        VRT::ContextInfo ci;
        if (VRT::parseContext(pkt + off, vrtLen, swap, &ci)) {
            rec->contextPackets++;
            rec->haveContext = true;
            if (ci.haveSampleRate) rec->sampleRate = ci.sampleRate;
            if (ci.haveRfFreq)     rec->rfFreq     = ci.rfFreq;
            if (ci.haveBandwidth)  rec->bandwidth  = ci.bandwidth;
            if (ci.haveFormat)     rec->format     = ci.format;
        }
        return;
    }

    if (h.type != VRT::PKT_SIGNAL_DATA && h.type != VRT::PKT_SIGNAL_DATA_NO_SID)
        return;

    /* The modulo-16 packet counter is the strongest signal that this really is
     * a VRT stream rather than some other protocol that happened to pass the
     * structural checks. Unrelated traffic will not step bits 19:16 by one on
     * every datagram. */
    static std::map<std::string, uint8_t> lastCount;
    std::string k = rec->key();
    auto it = lastCount.find(k);
    if (it != lastCount.end()) {
        if (h.count == (uint8_t)((it->second + 1) & 0xF))
            rec->seqRun++;
        else
            rec->seqRun = 0;
    }
    lastCount[k] = h.count;

    rec->dataPackets++;
    rec->payloadBytes += h.payloadBytes;
}

void prune(std::vector<StreamInfo> &table)
{
    table.erase(std::remove_if(table.begin(), table.end(),
        [](const StreamInfo &s) {
            return !(s.haveContext || s.seqRun >= 3);
        }), table.end());
}

/* Convert accumulated payload bytes into an approximate sample rate. Only
 * meaningful when the format is known, so it stays zero otherwise. */
static void finishRates(std::vector<StreamInfo> &table, int dwellMs)
{
    if (dwellMs <= 0)
        return;
    for (auto &s : table) {
        size_t bps = VRT::bytesPerSample(s.format);
        if (bps == 0)
            bps = 4;   /* assume ci16 when the source never sent a context */
        s.observedRate = (double)s.payloadBytes / (double)bps *
                         (1000.0 / (double)dwellMs);
    }
}

/* ------------------------------------------------------------------ */
/* Passive capture scan                                               */
/* ------------------------------------------------------------------ */

#ifdef HAVE_PCAP

/* Number of bytes to skip to reach the network header, by link type. */
static int linkHeaderLen(int dlt, const uint8_t *p, size_t caplen, uint16_t *etherType)
{
    switch (dlt) {
    case DLT_EN10MB: {
        if (caplen < 14) return -1;
        uint16_t et = (uint16_t)(p[12] << 8 | p[13]);
        int off = 14;
        /* Walk any number of stacked VLAN tags. */
        while ((et == 0x8100 || et == 0x88A8 || et == 0x9100) &&
               caplen >= (size_t)off + 4) {
            et = (uint16_t)(p[off + 2] << 8 | p[off + 3]);
            off += 4;
        }
        *etherType = et;
        return off;
    }
    case DLT_LINUX_SLL:
        if (caplen < 16) return -1;
        *etherType = (uint16_t)(p[14] << 8 | p[15]);
        return 16;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        if (caplen < 20) return -1;
        *etherType = (uint16_t)(p[0] << 8 | p[1]);
        return 20;
#endif
    case DLT_RAW:
        if (caplen < 1) return -1;
        *etherType = ((p[0] >> 4) == 6) ? 0x86DD : 0x0800;
        return 0;
    case DLT_NULL:
        if (caplen < 4) return -1;
        /* Host byte order family in the first word. */
        *etherType = (p[0] == 2 || p[3] == 2) ? 0x0800 : 0x86DD;
        return 4;
    default:
        return -1;
    }
}

struct CaptureCtx {
    std::vector<StreamInfo> *table;
    int dlt;
};

bool extractUdp(int linkType, const uint8_t *frame, size_t caplen,
                std::string *srcAddr, std::string *dstAddr, uint16_t *dstPort,
                const uint8_t **payload, size_t *payloadLen)
{
    const uint8_t *p = frame;

    uint16_t etherType = 0;
    int lhl = linkHeaderLen(linkType, p, caplen, &etherType);
    if (lhl < 0 || caplen < (size_t)lhl)
        return false;

    p += lhl;
    caplen -= lhl;

    char srcStr[INET6_ADDRSTRLEN] = "";
    char dstStr[INET6_ADDRSTRLEN] = "";
    size_t ipHdrLen = 0;

    if (etherType == 0x0800) {
        if (caplen < 20) return false;
        if ((p[0] >> 4) != 4) return false;
        ipHdrLen = (size_t)(p[0] & 0x0F) * 4;
        if (ipHdrLen < 20 || caplen < ipHdrLen) return false;
        if (p[9] != IPPROTO_UDP) return false;
        /* Only the first fragment carries the UDP header, and a fragmented
         * VRT packet cannot be length-checked, so later fragments are
         * dropped rather than misclassified. */
        uint16_t fragOff = (uint16_t)((p[6] << 8 | p[7]) & 0x1FFF);
        if (fragOff != 0) return false;
        inet_ntop(AF_INET, p + 12, srcStr, sizeof(srcStr));
        inet_ntop(AF_INET, p + 16, dstStr, sizeof(dstStr));
    } else if (etherType == 0x86DD) {
        if (caplen < 40) return false;
        if (p[6] != IPPROTO_UDP) return false;   /* no extension header walk */
        ipHdrLen = 40;
        inet_ntop(AF_INET6, p + 8,  srcStr, sizeof(srcStr));
        inet_ntop(AF_INET6, p + 24, dstStr, sizeof(dstStr));
    } else {
        return false;
    }

    p += ipHdrLen;
    caplen -= ipHdrLen;
    if (caplen < 8) return false;

    *dstPort = (uint16_t)(p[2] << 8 | p[3]);
    size_t udpLen = (size_t)(p[4] << 8 | p[5]);
    p += 8;
    caplen -= 8;

    size_t n = (udpLen >= 8) ? udpLen - 8 : 0;
    if (n == 0 || n > caplen)
        n = caplen;              /* truncated capture; use what we have */

    *srcAddr    = srcStr;
    *dstAddr    = dstStr;
    *payload    = p;
    *payloadLen = n;
    return true;
}

static void onPacket(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    CaptureCtx *ctx = (CaptureCtx *)user;

    std::string src, dst;
    uint16_t dstPort = 0;
    const uint8_t *payload = nullptr;
    size_t payloadLen = 0;

    if (!extractUdp(ctx->dlt, (const uint8_t *)bytes, hdr->caplen,
                    &src, &dst, &dstPort, &payload, &payloadLen))
        return;

    classify(*ctx->table, src, dst, dstPort, payload, payloadLen);
}

bool scanPcapFile(const std::string &path, std::vector<StreamInfo> &out,
                  std::string &err)
{
    char ebuf[PCAP_ERRBUF_SIZE] = "";
    pcap_t *pc = pcap_open_offline(path.c_str(), ebuf);
    if (pc == nullptr) {
        err = std::string("pcap_open_offline: ") + ebuf;
        return false;
    }

    CaptureCtx ctx;
    ctx.table = &out;
    ctx.dlt   = pcap_datalink(pc);

    pcap_loop(pc, 0, onPacket, (u_char *)&ctx);
    pcap_close(pc);

    prune(out);
    /* A file has no dwell time, so an observed rate cannot be inferred from
     * it without the capture timestamps; the context packets carry the
     * authoritative rate anyway. */
    return true;
}

bool scanPcap(const ScanOptions &opt, std::vector<StreamInfo> &out, std::string &err)
{
    char ebuf[PCAP_ERRBUF_SIZE] = "";

    pcap_t *pc = pcap_create(opt.iface.c_str(), ebuf);
    if (pc == nullptr) {
        err = std::string("pcap_create: ") + ebuf;
        return false;
    }

    pcap_set_snaplen(pc, 65535);
    pcap_set_promisc(pc, 1);
    pcap_set_timeout(pc, 100);
    pcap_set_immediate_mode(pc, 1);
    pcap_set_buffer_size(pc, 16 * 1024 * 1024);

    int rc = pcap_activate(pc);
    if (rc < 0) {
        err = std::string("pcap_activate(") + opt.iface + "): " + pcap_geterr(pc);
        if (rc == PCAP_ERROR_PERM_DENIED)
            err += " - grant capture rights with: sudo setcap "
                   "cap_net_raw,cap_net_admin+eip $(which SoapySDRUtil)";
        pcap_close(pc);
        return false;
    }

    struct bpf_program fp;
    if (pcap_compile(pc, &fp, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pc, &fp);
        pcap_freecode(&fp);
    }

    pcap_setnonblock(pc, 1, ebuf);

    CaptureCtx ctx;
    ctx.table = &out;
    ctx.dlt   = pcap_datalink(pc);

    int64_t deadline = nowMs() + opt.dwellMs;
    while (nowMs() < deadline) {
        int n = pcap_dispatch(pc, 256, onPacket, (u_char *)&ctx);
        if (n < 0)
            break;
        if (n == 0) {
            struct timespec ts = { 0, 5 * 1000 * 1000 };
            nanosleep(&ts, nullptr);
        }
    }

    struct pcap_stat st;
    if (opt.verbose && pcap_stats(pc, &st) == 0)
        fprintf(stderr, "vita49: capture received %u, dropped %u\n",
                st.ps_recv, st.ps_drop);

    pcap_close(pc);

    prune(out);
    finishRates(out, opt.dwellMs);
    return true;
}

#else  /* !HAVE_PCAP */

bool scanPcap(const ScanOptions &, std::vector<StreamInfo> &, std::string &err)
{
    err = "built without libpcap; only the bind scan is available";
    return false;
}

bool scanPcapFile(const std::string &, std::vector<StreamInfo> &, std::string &err)
{
    err = "built without libpcap; capture files cannot be replayed";
    return false;
}

bool extractUdp(int, const uint8_t *, size_t, std::string *, std::string *,
                uint16_t *, const uint8_t **, size_t *)
{
    return false;
}

#endif

/* ------------------------------------------------------------------ */
/* Bind scan                                                          */
/* ------------------------------------------------------------------ */

/* Raise the descriptor limit toward its hard ceiling so the whole port range
 * can be held open at once; a single long dwell finds far more than many
 * short ones. Returns the number of sockets we may safely open. */
static size_t raiseFdLimit(size_t wanted)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 256;

    rlim_t need = (rlim_t)wanted + 64;   /* headroom for the caller's own fds */
    if (rl.rlim_cur < need) {
        struct rlimit want = rl;
        want.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ? need
                                                       : std::min(need, rl.rlim_max);
        if (setrlimit(RLIMIT_NOFILE, &want) == 0)
            rl.rlim_cur = want.rlim_cur;
    }

    if (rl.rlim_cur <= 64)
        return 8;
    return std::min(wanted, (size_t)(rl.rlim_cur - 64));
}

static int openScanSocket(uint16_t port, const std::vector<std::string> &groups,
                          int rcvbuf)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;

    /* No SO_REUSEADDR: a scan that could bind a port another process is
     * already receiving on would take the traffic away from it. Ports in use
     * are skipped and counted instead, and a capture scan is the way to see
     * streams that something else is consuming. */

    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;   /* already in use, or privileged - skip it */
    }

    for (const auto &g : groups) {
        struct ip_mreq mr;
        memset(&mr, 0, sizeof(mr));
        if (inet_pton(AF_INET, g.c_str(), &mr.imr_multiaddr) == 1) {
            mr.imr_interface.s_addr = htonl(INADDR_ANY);
            setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr));
        }
    }

    return fd;
}

/* Receive from a ready socket and hand every datagram to the classifier. */
static void drainSocket(int fd, uint16_t port, std::vector<StreamInfo> &table,
                        std::vector<uint8_t> &buf)
{
    for (;;) {
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                             (struct sockaddr *)&from, &fromLen);
        if (n <= 0)
            return;

        char srcStr[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &from.sin_addr, srcStr, sizeof(srcStr));

        /* The bind scan cannot tell unicast from multicast after the fact, so
         * the destination is recorded as the wildcard the socket bound to.
         * A later capture scan refines it if one ever runs. */
        classify(table, srcStr, "0.0.0.0", port, buf.data(), (size_t)n);
    }
}

/* Wait on a batch of sockets until the deadline, draining whatever arrives. */
static void dwellOnSockets(const std::vector<int> &fds,
                           const std::vector<uint16_t> &ports,
                           int64_t deadline, std::vector<StreamInfo> &table)
{
    std::vector<uint8_t> buf(65536);

#ifdef __linux__
    int ep = epoll_create1(0);
    if (ep < 0)
        return;

    for (size_t i = 0; i < fds.size(); i++) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events  = EPOLLIN;
        ev.data.u32 = (uint32_t)i;
        epoll_ctl(ep, EPOLL_CTL_ADD, fds[i], &ev);
    }

    std::vector<struct epoll_event> evs(256);
    for (;;) {
        int64_t left = deadline - nowMs();
        if (left <= 0)
            break;
        int n = epoll_wait(ep, evs.data(), (int)evs.size(), (int)left);
        if (n <= 0)
            continue;
        for (int i = 0; i < n; i++) {
            uint32_t idx = evs[i].data.u32;
            if (idx < fds.size())
                drainSocket(fds[idx], ports[idx], table, buf);
        }
    }

    close(ep);
#else
    std::vector<struct pollfd> pfds(fds.size());
    for (size_t i = 0; i < fds.size(); i++) {
        pfds[i].fd     = fds[i];
        pfds[i].events = POLLIN;
    }
    for (;;) {
        int64_t left = deadline - nowMs();
        if (left <= 0)
            break;
        int n = poll(pfds.data(), pfds.size(), (int)left);
        if (n <= 0)
            continue;
        for (size_t i = 0; i < pfds.size(); i++) {
            if (pfds[i].revents & POLLIN)
                drainSocket(fds[i], ports[i], table, buf);
        }
    }
#endif
}

bool scanBind(const ScanOptions &opt, std::vector<StreamInfo> &out, std::string &err)
{
    /* Well-known ports first so that a truncated scan still finds the common
     * case, then everything else in the requested range. */
    std::vector<uint16_t> ports;
    std::vector<bool> seen(65536, false);

    for (size_t i = 0; i < kWellKnownPortCount; i++) {
        uint16_t p = kWellKnownPorts[i];
        if (opt.wellKnownOnly || (p >= opt.portLow && p <= opt.portHigh)) {
            if (!seen[p]) {
                ports.push_back(p);
                seen[p] = true;
            }
        }
    }
    if (!opt.wellKnownOnly) {
        for (unsigned p = std::max<unsigned>(opt.portLow, 1); p <= opt.portHigh; p++) {
            if (!seen[p]) {
                ports.push_back((uint16_t)p);
                seen[p] = true;
            }
        }
    }

    size_t budget = raiseFdLimit(ports.size());
    size_t batch  = std::min(budget, (size_t)std::max(opt.batchSize, 1));
    if (budget >= ports.size())
        batch = ports.size();   /* one pass, one long dwell - much better odds */

    size_t batches = (ports.size() + batch - 1) / batch;
    int perBatchMs = (int)std::max<int64_t>(50, opt.dwellMs / (int64_t)batches);

    if (opt.verbose)
        fprintf(stderr, "vita49: bind scan %zu ports in %zu pass(es), %d ms each\n",
                ports.size(), batches, perBatchMs);

    /* Split one memory budget across the sockets rather than fix a size. A
     * sweep of every port needs small buffers to stay affordable, but a scan
     * of a handful wants them large: at tens of megasamples a second a small
     * buffer overflows between the once-a-second context packets, which is
     * what carries the rate and frequency. */
    const size_t kScanBufBudget = 256u * 1024 * 1024;
    int perSocketBuf = (int)(kScanBufBudget / std::max<size_t>(batch, 1));
    perSocketBuf = std::max(perSocketBuf, 64 * 1024);
    perSocketBuf = std::min(perSocketBuf, 16 * 1024 * 1024);

    size_t bound = 0, refused = 0;

    for (size_t base = 0; base < ports.size(); base += batch) {
        size_t n = std::min(batch, ports.size() - base);

        std::vector<int>      fds;
        std::vector<uint16_t> fdPorts;
        fds.reserve(n);
        fdPorts.reserve(n);

        for (size_t i = 0; i < n; i++) {
            int fd = openScanSocket(ports[base + i], opt.mcastGroups, perSocketBuf);
            if (fd < 0) { refused++; continue; }
            fds.push_back(fd);
            fdPorts.push_back(ports[base + i]);
        }
        bound += fds.size();

        if (!fds.empty())
            dwellOnSockets(fds, fdPorts, nowMs() + perBatchMs, out);

        for (int fd : fds)
            close(fd);
    }

    if (bound == 0) {
        err = "bind scan could not open any port in the requested range";
        return false;
    }
    if (opt.verbose && refused)
        fprintf(stderr, "vita49: %zu port(s) already in use, skipped\n", refused);

    prune(out);
    finishRates(out, opt.dwellMs);
    return true;
}

/* TODO: this listens only to endpoints already in the cache, so a source that
 * moves to a different port looks idle rather than relocated. Detecting that
 * would need a scan, which is too slow to run on every enumeration. */
void verifyLiveness(std::vector<StreamInfo> &entries, int dwellMs)
{
    if (entries.empty() || dwellMs <= 0)
        return;

    /* One socket per distinct endpoint, not per stream: several stream IDs
     * commonly share a port. */
    struct Ep { std::string addr; uint16_t port; int fd; bool busy; };
    std::vector<Ep> eps;

    for (const auto &e : entries) {
        bool known = false;
        for (const auto &x : eps)
            if (x.port == e.dstPort && x.addr == e.dstAddr) { known = true; break; }
        if (known)
            continue;

        Ep ep;
        ep.addr = e.dstAddr;
        ep.port = e.dstPort;
        ep.busy = false;
        ep.fd   = openScanSocket(e.dstPort, std::vector<std::string>(),
                                 8 * 1024 * 1024);
        if (ep.fd < 0)
            ep.busy = true;   /* held by another process, so something wants it */
        eps.push_back(ep);
    }

    std::vector<StreamInfo> seen;
    std::vector<int>      fds;
    std::vector<uint16_t> ports;
    for (const auto &ep : eps) {
        if (ep.fd >= 0) { fds.push_back(ep.fd); ports.push_back(ep.port); }
    }
    if (!fds.empty())
        dwellOnSockets(fds, ports, nowMs() + dwellMs, seen);
    for (int fd : fds)
        close(fd);

    for (auto &e : entries) {
        bool busy = false;
        for (const auto &ep : eps)
            if (ep.port == e.dstPort && ep.addr == e.dstAddr) { busy = ep.busy; break; }

        if (busy) {
            e.liveness = StreamInfo::LIVE_BUSY;
            continue;
        }

        e.liveness = StreamInfo::LIVE_IDLE;
        for (const auto &s : seen) {
            if (s.dstPort != e.dstPort || s.streamId != e.streamId)
                continue;
            e.liveness = StreamInfo::LIVE_STREAMING;
            e.lastSeen = nowUnix();
            /* A context packet caught here is fresher than the cache. */
            if (s.haveContext) {
                e.haveContext = true;
                if (s.sampleRate > 0.0) e.sampleRate = s.sampleRate;
                if (s.rfFreq > 0.0)     e.rfFreq     = s.rfFreq;
                if (s.bandwidth > 0.0)  e.bandwidth  = s.bandwidth;
                if (s.format != VRT::FMT_UNKNOWN) e.format = s.format;
            }
            break;
        }
    }
}

bool probeEndpoint(const std::string &bindAddr, uint16_t port, int dwellMs,
                   std::vector<StreamInfo> &out, std::string &err)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        err = std::string("socket: ") + strerror(errno);
        return false;
    }

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct in_addr target;
    if (inet_pton(AF_INET, bindAddr.c_str(), &target) != 1)
        target.s_addr = htonl(INADDR_ANY);

    bool isMulticast = (ntohl(target.s_addr) >= 0xE0000000u &&
                        ntohl(target.s_addr) <  0xF0000000u);

    /* Linux needs the option on every socket sharing a port, so a probe that
     * omitted it would block other processes from joining the group for as
     * long as it held the port. Unicast is left without it: a probe must not
     * take traffic from an application already receiving. */
    if (isMulticast) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    /* A multicast address must be joined, not bound to as a source; binding
     * the wildcard and joining the group is what actually receives it. */
    sa.sin_addr.s_addr = isMulticast ? htonl(INADDR_ANY) : target.s_addr;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        err = std::string("bind ") + bindAddr + ":" + std::to_string(port) +
              ": " + strerror(errno);
        close(fd);
        return false;
    }

    if (isMulticast) {
        struct ip_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.imr_multiaddr = target;
        mr.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
            err = std::string("join ") + bindAddr + ": " + strerror(errno);
            close(fd);
            return false;
        }
    }

    std::vector<int>      fds{fd};
    std::vector<uint16_t> pl{port};
    dwellOnSockets(fds, pl, nowMs() + dwellMs, out);
    close(fd);

    for (auto &s : out)
        s.dstAddr = bindAddr;

    prune(out);
    finishRates(out, dwellMs);
    return true;
}

std::vector<StreamInfo> scanAuto(const ScanOptions &opt, std::string &note)
{
    std::vector<StreamInfo> out;
    std::string err;

    if (opt.allowPcap && scanPcap(opt, out, err)) {
        note = "capture scan";
    } else {
        if (!err.empty())
            note = "capture unavailable (" + err + "); ";
        if (opt.allowBind) {
            std::string berr;
            if (scanBind(opt, out, berr))
                note += "bind scan";
            else
                note += "bind scan failed: " + berr;
        }
    }

    std::string cerr;
    cacheMerge(out, cerr);
    return out;
}

/* ------------------------------------------------------------------ */
/* Cache                                                              */
/* ------------------------------------------------------------------ */

std::string cachePath()
{
    const char *env = getenv("SOAPY_VITA49_CACHE");
    if (env && *env)
        return std::string(env);

    std::string base;
    const char *xdg = getenv("XDG_CACHE_HOME");
    if (xdg && *xdg) {
        base = xdg;
    } else {
        const char *home = getenv("HOME");
        base = std::string(home ? home : "/tmp") + "/.cache";
    }
    base += "/SoapyVITA49";
    mkdir(base.c_str(), 0755);
    return base + "/streams.conf";
}

/* The cache is a line-oriented key=value list rather than JSON so it stays
 * trivially greppable and hand-editable, which matters when a site needs to
 * pin a stream that only appears intermittently. */
std::vector<StreamInfo> cacheLoad(int maxAgeSec)
{
    std::vector<StreamInfo> out;

    FILE *f = fopen(cachePath().c_str(), "r");
    if (f == nullptr)
        return out;

    int64_t cutoff = (maxAgeSec > 0) ? nowUnix() - maxAgeSec : 0;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (strncmp(line, "stream ", 7) != 0)
            continue;

        StreamInfo s;
        s.hasStreamId = true;

        char *save = nullptr;
        for (char *tok = strtok_r(line + 7, " \t\r\n", &save); tok;
             tok = strtok_r(nullptr, " \t\r\n", &save)) {
            char *eq = strchr(tok, '=');
            if (eq == nullptr) continue;
            *eq = '\0';
            const char *k = tok, *v = eq + 1;

            if      (!strcmp(k, "dst"))  s.dstAddr    = v;
            else if (!strcmp(k, "src"))  s.srcAddr    = v;
            else if (!strcmp(k, "port")) s.dstPort    = (uint16_t)strtoul(v, nullptr, 10);
            else if (!strcmp(k, "sid"))  s.streamId   = (uint32_t)strtoul(v, nullptr, 0);
            else if (!strcmp(k, "hassid")) s.hasStreamId = (atoi(v) != 0);
            else if (!strcmp(k, "rate")) s.sampleRate = atof(v);
            else if (!strcmp(k, "freq")) s.rfFreq     = atof(v);
            else if (!strcmp(k, "bw"))   s.bandwidth  = atof(v);
            else if (!strcmp(k, "hdrswap")) s.hdrSwap  = (atoi(v) != 0);
            else if (!strcmp(k, "datswap")) s.dataSwap = (atoi(v) != 0);
            else if (!strcmp(k, "vrl"))  s.vrlFramed  = (atoi(v) != 0);
            else if (!strcmp(k, "ctx"))  s.haveContext = (atoi(v) != 0);
            else if (!strcmp(k, "seen")) s.lastSeen   = strtoll(v, nullptr, 10);
            else if (!strcmp(k, "fmt")) {
                if      (!strcmp(v, "ci8"))  s.format = VRT::FMT_CI8;
                else if (!strcmp(v, "ci12")) s.format = VRT::FMT_CI12;
                else if (!strcmp(v, "ci16")) s.format = VRT::FMT_CI16;
                else if (!strcmp(v, "cf32")) s.format = VRT::FMT_CF32;
            }
        }

        if (s.dstPort == 0)
            continue;
        if (cutoff > 0 && s.lastSeen < cutoff)
            continue;

        s.seqRun = 3;   /* cached entries were already vetted when written */
        out.push_back(s);
    }

    fclose(f);
    return out;
}

bool cacheStore(const std::vector<StreamInfo> &streams, std::string &err)
{
    std::string path = cachePath();
    std::string tmp  = path + ".tmp";

    FILE *f = fopen(tmp.c_str(), "w");
    if (f == nullptr) {
        err = std::string("open ") + tmp + ": " + strerror(errno);
        return false;
    }

    fprintf(f, "# SoapyVITA49 discovered streams\n"
               "# Written by the discovery scanner; safe to edit by hand.\n"
               "# Fields: dst port sid hassid src fmt rate freq bw hdrswap "
               "datswap vrl ctx seen\n");

    for (const auto &s : streams) {
        fprintf(f, "stream dst=%s port=%u sid=0x%08x hassid=%d src=%s fmt=%s "
                   "rate=%.0f freq=%.0f bw=%.0f hdrswap=%d datswap=%d "
                   "vrl=%d ctx=%d seen=%lld\n",
                s.dstAddr.empty() ? "0.0.0.0" : s.dstAddr.c_str(),
                s.dstPort, s.streamId, s.hasStreamId ? 1 : 0,
                s.srcAddr.empty() ? "-" : s.srcAddr.c_str(),
                VRT::formatName(s.format),
                s.sampleRate, s.rfFreq, s.bandwidth,
                s.hdrSwap ? 1 : 0, s.dataSwap ? 1 : 0,
                s.vrlFramed ? 1 : 0, s.haveContext ? 1 : 0,
                (long long)s.lastSeen);
    }

    fclose(f);

    if (rename(tmp.c_str(), path.c_str()) != 0) {
        err = std::string("rename ") + tmp + ": " + strerror(errno);
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool cacheMerge(const std::vector<StreamInfo> &fresh, std::string &err)
{
    /* Keep old entries so a stream that is merely idle right now does not
     * disappear from device lists, but let a fresh observation win. */
    std::vector<StreamInfo> merged = cacheLoad(0);

    for (const auto &f : fresh) {
        bool replaced = false;
        for (auto &m : merged) {
            if (m.dstPort == f.dstPort && m.streamId == f.streamId &&
                (m.dstAddr == f.dstAddr || m.dstAddr == "0.0.0.0" ||
                 f.dstAddr == "0.0.0.0")) {
                StreamInfo keep = f;
                if (keep.dstAddr == "0.0.0.0" && m.dstAddr != "0.0.0.0")
                    keep.dstAddr = m.dstAddr;
                /* Retain metadata the new sighting did not carry. */
                if (!keep.haveContext) {
                    if (keep.sampleRate == 0.0) keep.sampleRate = m.sampleRate;
                    if (keep.rfFreq     == 0.0) keep.rfFreq     = m.rfFreq;
                    if (keep.bandwidth  == 0.0) keep.bandwidth  = m.bandwidth;
                    if (keep.format == VRT::FMT_UNKNOWN) keep.format = m.format;
                }
                m = keep;
                replaced = true;
                break;
            }
        }
        if (!replaced)
            merged.push_back(f);
    }

    return cacheStore(merged, err);
}

} /* namespace Discovery */
