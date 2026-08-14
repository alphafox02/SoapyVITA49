/*
 * vita49-dump: decode VITA 49 packets field by field.
 *
 * Reads a live UDP endpoint or a capture file and reports the contents of each
 * packet: stream identifiers, packet classes, timestamps, context fields,
 * trailer indicators and byte order.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Convert.hpp"
#include "Discovery.hpp"
#include "VRT.hpp"

#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

static volatile sig_atomic_t g_run = 1;
static void onSignal(int) { g_run = 0; }

static int  g_maxPackets  = 0;      /* 0 = unlimited */
static int  g_seconds     = 0;      /* 0 = unlimited */
static int  g_dataEvery   = 0;      /* print one data packet in N, 0 = none */
static bool g_hex         = false;
static bool g_forceSwap   = false;
static bool g_swapSet     = false;

static double g_elapsedSec = 0.0;
static long g_seen = 0, g_data = 0, g_context = 0, g_command = 0, g_other = 0;
static std::map<uint32_t, long> g_bySid;

static const char *tsiName(VRT::TSI t)
{
    switch (t) {
    case VRT::TSI_NONE:  return "none";
    case VRT::TSI_UTC:   return "UTC";
    case VRT::TSI_GPS:   return "GPS";
    default:             return "other";
    }
}

static const char *tsfName(VRT::TSF t)
{
    switch (t) {
    case VRT::TSF_NONE:         return "none";
    case VRT::TSF_SAMPLE_COUNT: return "sample count";
    case VRT::TSF_REALTIME_PS:  return "real time (ps)";
    default:                    return "free running";
    }
}

static const char *typeName(VRT::PacketType t)
{
    switch (t) {
    case VRT::PKT_SIGNAL_DATA_NO_SID: return "signal data (no stream ID)";
    case VRT::PKT_SIGNAL_DATA:        return "signal data";
    case VRT::PKT_EXT_DATA_NO_SID:    return "extension data (no stream ID)";
    case VRT::PKT_EXT_DATA:           return "extension data";
    case VRT::PKT_IF_CONTEXT:         return "IF context";
    case VRT::PKT_EXT_CONTEXT:        return "extension context";
    case VRT::PKT_COMMAND:            return "command (49.2)";
    case VRT::PKT_EXT_COMMAND:        return "extension command (49.2)";
    default:                          return "reserved";
    }
}

static void hexDump(const uint8_t *p, size_t n, size_t limit)
{
    size_t show = (limit && n > limit) ? limit : n;
    for (size_t i = 0; i < show; i += 16) {
        printf("      %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < show) printf("%02x ", p[i + j]);
            else              printf("   ");
            if (j == 7) printf(" ");
        }
        printf("\n");
    }
    if (show < n)
        printf("      ... %zu more bytes\n", n - show);
}

static void dumpContext(const uint8_t *vrt, size_t len, bool swap)
{
    VRT::ContextInfo ci;
    if (!VRT::parseContext(vrt, len, swap, &ci)) {
        printf("      context did not decode\n");
        return;
    }

    if (ci.changeIndicator)
        printf("      change indicator set\n");
    if (ci.haveRfFreq)
        printf("      RF reference frequency  %.6f MHz\n", ci.rfFreq / 1e6);
    if (ci.haveIfFreq)
        printf("      IF reference frequency  %.6f MHz\n", ci.ifFreq / 1e6);
    if (ci.haveSampleRate)
        printf("      sample rate             %.0f Hz (%.6f Msps)\n",
               ci.sampleRate, ci.sampleRate / 1e6);
    if (ci.haveBandwidth)
        printf("      bandwidth               %.0f Hz (%.6f MHz)\n",
               ci.bandwidth, ci.bandwidth / 1e6);
    if (ci.haveGain)
        printf("      gain                    stage1 %.2f dB, stage2 %.2f dB\n",
               ci.gainStage1, ci.gainStage2);
    if (ci.haveRefLevel)
        printf("      reference level         %.2f dBm\n", ci.refLevel);
    if (ci.haveTemperature)
        printf("      temperature             %.2f C\n", ci.temperature);
    if (ci.haveOverRange)
        printf("      over-range count        %u\n", ci.overRange);
    if (ci.haveDeviceId)
        printf("      device identifier       OUI %02X-%02X-%02X, device 0x%04x\n",
               (ci.deviceOui >> 16) & 0xFF, (ci.deviceOui >> 8) & 0xFF,
               ci.deviceOui & 0xFF, ci.deviceCode);

    if (ci.haveFormat) {
        printf("      payload format          %s, %s packing, "
               "%u-bit items in %u-bit fields\n",
               VRT::formatName(ci.format),
               ci.linkEfficient ? "link-efficient" : "processing-efficient",
               ci.itemSizeBits, ci.packingBits);
    } else {
        printf("      payload format          NOT PRESENT - the receiver has to "
               "be told the format with format=\n");
    }
}

static void dumpPacket(const std::string &src, const std::string &dst,
                       uint16_t dstPort, const uint8_t *pkt, size_t len)
{
    g_seen++;

    bool swap = g_swapSet ? g_forceSwap : false;
    if (!g_swapSet) {
        bool detected = false;
        if (VRT::looksLikeVRT(pkt, len, &detected))
            swap = detected;
    }

    size_t vrtLen = 0;
    size_t off = VRT::vrlStrip(pkt, len, &vrtLen);

    VRT::Header h;
    if (!VRT::parseHeader(pkt + off, vrtLen, swap, &h)) {
        printf("[%ld] %s -> %s:%u  %zu bytes  DID NOT DECODE as VRT\n",
               g_seen, src.c_str(), dst.c_str(), dstPort, len);
        if (g_hex) hexDump(pkt, len, 64);
        g_other++;
        return;
    }

    bool isData = (h.type == VRT::PKT_SIGNAL_DATA ||
                   h.type == VRT::PKT_SIGNAL_DATA_NO_SID);
    if (isData)                        g_data++;
    else if (h.type == VRT::PKT_IF_CONTEXT ||
             h.type == VRT::PKT_EXT_CONTEXT) g_context++;
    else if (h.type == VRT::PKT_COMMAND ||
             h.type == VRT::PKT_EXT_COMMAND) g_command++;
    else                               g_other++;

    if (h.hasStreamId)
        g_bySid[h.streamId]++;

    /* Data packets are far too numerous to print in full, so only every Nth
     * one is shown while every context and command packet is. */
    if (isData && (g_dataEvery == 0 || (g_data % g_dataEvery) != 1))
        return;

    printf("\n[%ld] %s -> %s:%u  %zu bytes\n",
           g_seen, src.c_str(), dst.c_str(), dstPort, len);
    printf("      %s, %zu words (%zu bytes)%s\n",
           typeName(h.type), h.sizeWords, h.sizeWords * 4,
           (off != 0) ? ", inside a VRL frame" : "");
    printf("      header byte order       %s\n",
           swap ? "LITTLE endian" : "big endian");

    if (h.sizeWords * 4 != vrtLen)
        printf("      NOTE declared size %zu differs from datagram payload %zu\n",
               h.sizeWords * 4, vrtLen);

    if (h.hasStreamId) printf("      stream ID               0x%08x\n", h.streamId);
    else               printf("      stream ID               absent (packet type %d)\n",
                              (int)h.type);
    if (h.hasClassId)
        printf("      class ID                OUI 0x%06x, info 0x%04x, packet 0x%04x\n",
               (unsigned)((h.classId >> 32) & 0x00FFFFFF),
               (unsigned)((h.classId >> 16) & 0xFFFF),
               (unsigned)(h.classId & 0xFFFF));
    if (h.hasTrailer) {
        VRT::Trailer tr;
        if (VRT::parseTrailer(pkt + off, h, swap, &tr)) {
            printf("      trailer                ");
            bool any = false;
            struct { bool have, value; const char *name; } f[] = {
                { tr.haveCalibratedTime, tr.calibratedTime, "calibrated-time" },
                { tr.haveValidData,      tr.validData,      "valid-data"      },
                { tr.haveReferenceLock,  tr.referenceLock,  "ref-lock"        },
                { tr.haveAgc,            tr.agc,            "agc"             },
                { tr.haveDetectedSignal, tr.detectedSignal, "detected-signal" },
                { tr.haveSpectralInv,    tr.spectralInv,    "spectral-inv"    },
                { tr.haveOverRange,      tr.overRange,      "OVER-RANGE"      },
                { tr.haveSampleLoss,     tr.sampleLoss,     "SAMPLE-LOSS"     },
            };
            for (const auto &x : f) {
                if (!x.have) continue;
                printf(" %s=%s", x.name, x.value ? "yes" : "no");
                any = true;
            }
            if (tr.haveContextCount)
                printf(" ctx-count=%u", tr.contextCount);
            if (!any && !tr.haveContextCount)
                printf(" present, no indicators enabled");
            printf("\n");
        } else {
            printf("      trailer present\n");
        }
    }

    printf("      timestamp               TSI %s, TSF %s\n",
           tsiName(h.tsi), tsfName(h.tsf));
    if (h.tsi != VRT::TSI_NONE || h.tsf != VRT::TSF_NONE) {
        printf("                              integer %u, fractional %llu\n",
               h.tsInt, (unsigned long long)h.tsFrac);
        if (h.tsi == VRT::TSI_UTC || h.tsi == VRT::TSI_GPS) {
            /* GPS time counts from 1980-01-06 and ignores leap seconds. */
            time_t t = (time_t)h.tsInt + (h.tsi == VRT::TSI_GPS ? 315964800 : 0);
            char buf[64];
            struct tm tmv;
            gmtime_r(&t, &tmv);
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmv);

            /* An undisciplined source is usually wrong by a large, obvious
             * amount, so show the offset rather than leave it to be worked
             * out from two timestamps. */
            double off = difftime(time(nullptr), t);
            char note[96] = "";
            if (fabs(off) < 2.0)
                snprintf(note, sizeof(note), "  (matches this host)");
            else if (fabs(off) < 90.0)
                snprintf(note, sizeof(note), "  (%+.0f s vs this host)", off);
            else if (fabs(off) < 86400.0)
                snprintf(note, sizeof(note), "  (%+.1f hours vs this host)",
                         off / 3600.0);
            else
                snprintf(note, sizeof(note), "  (%+.1f days vs this host - source clock "
                         "is not disciplined)", off / 86400.0);
            printf("                              %s%s\n", buf, note);
        }
    }
    printf("      packet count            %u (modulo 16)\n", h.count);
    printf("      payload                 %zu bytes at offset %zu\n",
           h.payloadBytes, h.payloadOffset);

    if (h.type == VRT::PKT_IF_CONTEXT || h.type == VRT::PKT_EXT_CONTEXT)
        dumpContext(pkt + off, vrtLen, swap);

    if (h.type == VRT::PKT_COMMAND || h.type == VRT::PKT_EXT_COMMAND) {
        uint32_t w0 = VRT::rd32(pkt + off, swap);
        printf("      %s packet\n",
               (w0 & (1u << 26)) ? "ACKNOWLEDGE" : "control");
        if (h.payloadOffset / 4 + 2 <= h.sizeWords) {
            uint32_t cam = VRT::rd32(pkt + off + h.payloadOffset, swap);
            uint32_t mid = VRT::rd32(pkt + off + h.payloadOffset + 4, swap);
            printf("      CAM 0x%08x, message ID %u\n", cam, mid);
        }
    }

    if (g_hex)
        hexDump(pkt + off, vrtLen, isData ? 64 : 0);
}

static void printSummary()
{
    printf("\n----------------------------------------------------------\n");
    printf("%ld packets: %ld data, %ld context, %ld command, %ld other\n",
           g_seen, g_data, g_context, g_command, g_other);

    if (!g_bySid.empty()) {
        printf("stream IDs seen:\n");
        for (const auto &kv : g_bySid)
            printf("   0x%08x  %ld packets\n", kv.first, kv.second);
    }

    if (g_context == 0 && g_data > 0) {
        if (g_elapsedSec >= 2.0)
            printf("\nNo context packets in %.1f s. Sample rate, frequency and\n"
                   "payload format must then be supplied with rate=, freq= and\n"
                   "format= when opening the device.\n", g_elapsedSec);
        else
            printf("\nNo context packets seen, but only %.2f s of traffic was\n"
                   "examined. Context is usually sent about once a second, so\n"
                   "re-run with -T 5 before concluding there is none.\n",
                   g_elapsedSec);
    }
}

#ifdef HAVE_PCAP
struct FileCtx { int dlt; };
static struct timeval g_firstTs = {0, 0}, g_lastTs = {0, 0};

static void onCaptured(u_char *user, const struct pcap_pkthdr *hdr,
                       const u_char *bytes)
{
    if (!g_run) return;
    if (g_maxPackets && g_seen >= g_maxPackets) { g_run = 0; return; }

    if (g_firstTs.tv_sec == 0) g_firstTs = hdr->ts;
    g_lastTs = hdr->ts;

    FileCtx *ctx = (FileCtx *)user;
    std::string src, dst;
    uint16_t dstPort = 0;
    const uint8_t *payload = nullptr;
    size_t payloadLen = 0;

    if (!Discovery::extractUdp(ctx->dlt, (const uint8_t *)bytes, hdr->caplen,
                               &src, &dst, &dstPort, &payload, &payloadLen))
        return;

    dumpPacket(src, dst, dstPort, payload, payloadLen);
}
#endif

static int runLive(const std::string &addr, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct in_addr target;
    bool haveAddr = (inet_pton(AF_INET, addr.c_str(), &target) == 1);
    bool isMulticast = haveAddr && (ntohl(target.s_addr) >> 28) == 0xE;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr.s_addr = (haveAddr && !isMulticast) ? target.s_addr
                                                    : htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "bind %s:%u: %s\n", addr.c_str(), port, strerror(errno));
        close(fd);
        return 1;
    }

    if (isMulticast) {
        struct ip_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.imr_multiaddr = target;
        mr.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
            fprintf(stderr, "join %s: %s\n", addr.c_str(), strerror(errno));
            close(fd);
            return 1;
        }
        fprintf(stderr, "joined multicast group %s\n", addr.c_str());
    }

    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    fprintf(stderr, "listening on %s:%u, press Ctrl-C to stop\n\n",
            addr.c_str(), port);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    std::vector<uint8_t> buf(65536);
    while (g_run) {
        if (g_seconds > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - t0.tv_sec >= g_seconds)
                break;
        }
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0)
            continue;

        char srcStr[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &from.sin_addr, srcStr, sizeof(srcStr));
        dumpPacket(srcStr, addr, port, buf.data(), (size_t)n);

        if (g_maxPackets && g_seen >= g_maxPackets)
            break;
    }

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    g_elapsedSec = (double)(t1.tv_sec - t0.tv_sec) +
                   (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    close(fd);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s [-e ADDR:PORT | -f FILE.pcap] [options]\n"
"\n"
"Decodes VITA 49 packets field by field so an unfamiliar source can be\n"
"characterised: which stream IDs it uses, whether it sends context packets,\n"
"what payload format it declares, and which byte order it uses.\n"
"\n"
"  -e ADDR:PORT  listen on a UDP endpoint (a multicast group is joined)\n"
"  -f FILE       replay a capture file instead\n"
"  -n COUNT      stop after COUNT packets\n"
"  -T SECONDS    stop after SECONDS (preferred: context packets are\n"
"                typically only sent once a second)\n"
"  -d N          also print one data packet in every N (default: none)\n"
"  -x            include hex dumps\n"
"  -L, -B        force little or big endian headers instead of detecting\n",
        argv0);
}

int main(int argc, char **argv)
{
    std::string endpoint, file;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-e") && i + 1 < argc) endpoint = argv[++i];
        else if (!strcmp(a, "-f") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(a, "-n") && i + 1 < argc) g_maxPackets = atoi(argv[++i]);
        else if (!strcmp(a, "-T") && i + 1 < argc) g_seconds = atoi(argv[++i]);
        else if (!strcmp(a, "-d") && i + 1 < argc) g_dataEvery = atoi(argv[++i]);
        else if (!strcmp(a, "-x")) g_hex = true;
        else if (!strcmp(a, "-L")) { g_forceSwap = true;  g_swapSet = true; }
        else if (!strcmp(a, "-B")) { g_forceSwap = false; g_swapSet = true; }
        else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 1; }
    }

    if (endpoint.empty() && file.empty()) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);

    int rc = 0;

    if (!file.empty()) {
#ifdef HAVE_PCAP
        char ebuf[PCAP_ERRBUF_SIZE] = "";
        pcap_t *pc = pcap_open_offline(file.c_str(), ebuf);
        if (pc == nullptr) {
            fprintf(stderr, "cannot open %s: %s\n", file.c_str(), ebuf);
            return 1;
        }
        FileCtx ctx;
        ctx.dlt = pcap_datalink(pc);
        fprintf(stderr, "replaying %s\n\n", file.c_str());
        pcap_loop(pc, 0, onCaptured, (u_char *)&ctx);
        pcap_close(pc);
        g_elapsedSec = (double)(g_lastTs.tv_sec - g_firstTs.tv_sec) +
                       (double)(g_lastTs.tv_usec - g_firstTs.tv_usec) / 1e6;
#else
        fprintf(stderr, "built without libpcap; capture files cannot be read\n");
        return 1;
#endif
    } else {
        std::string addr = "0.0.0.0";
        uint16_t port = 4991;
        size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos) {
            port = (uint16_t)atoi(endpoint.c_str());
        } else {
            addr = endpoint.substr(0, colon);
            port = (uint16_t)atoi(endpoint.c_str() + colon + 1);
        }
        rc = runLive(addr, port);
    }

    printSummary();
    return rc;
}
