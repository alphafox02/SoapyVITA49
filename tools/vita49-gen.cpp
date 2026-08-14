/*
 * vita49-gen: emit a synthetic VITA 49 stream for testing a receiver.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Convert.hpp"
#include "VRT.hpp"

#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_run = 1;

static void onSignal(int) { g_run = 0; }

static long long monotonicNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static long long realtimeNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s [options]\n"
"\n"
"Generates a VITA 49 signal data stream with periodic IF context packets.\n"
"Useful for exercising a receiver without hardware.\n"
"\n"
"  -d ADDR      destination address (default: 127.0.0.1)\n"
"  -p PORT      destination port (default: 4991)\n"
"  -s SID       stream ID, decimal or 0x hex (default: 0x1)\n"
"  -r RATE      sample rate in Hz (default: 1000000)\n"
"  -f FREQ      reported RF frequency in Hz (default: 100000000)\n"
"  -F FORMAT    ci8, ci12, ci16 or cf32 (default: ci16)\n"
"  -m MTU       UDP payload budget in bytes (default: 1472)\n"
"  -T HZ        tone offset from centre in Hz (default: rate/8)\n"
"  -c PER_SEC   context packets per second (default: 1)\n"
"  -L           emit little-endian headers and samples\n"
"  -N           omit the stream ID, using packet type 0\n"
"  -n COUNT     stop after COUNT data packets\n",
        argv0);
}

int main(int argc, char **argv)
{
    std::string dest = "127.0.0.1";
    uint16_t port    = 4991;
    uint32_t sid     = 1;
    double rate      = 1.0e6;
    double freq      = 1.0e8;
    double tone      = 0.0;
    double ctxPerSec = 1.0;
    size_t mtu       = 1472;
    bool little      = false;
    bool noSid       = false;
    long long limit  = 0;
    VRT::SampleFormat wire = VRT::FMT_CI16;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-d") && i + 1 < argc) dest = argv[++i];
        else if (!strcmp(a, "-p") && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(a, "-s") && i + 1 < argc)
            sid = (uint32_t)strtoul(argv[++i], nullptr, 0);
        else if (!strcmp(a, "-r") && i + 1 < argc) rate = atof(argv[++i]);
        else if (!strcmp(a, "-f") && i + 1 < argc) freq = atof(argv[++i]);
        else if (!strcmp(a, "-T") && i + 1 < argc) tone = atof(argv[++i]);
        else if (!strcmp(a, "-c") && i + 1 < argc) ctxPerSec = atof(argv[++i]);
        else if (!strcmp(a, "-m") && i + 1 < argc) mtu = (size_t)atoi(argv[++i]);
        else if (!strcmp(a, "-n") && i + 1 < argc) limit = atoll(argv[++i]);
        else if (!strcmp(a, "-L")) little = true;
        else if (!strcmp(a, "-N")) noSid = true;
        else if (!strcmp(a, "-F") && i + 1 < argc) {
            const char *f = argv[++i];
            if      (!strcmp(f, "ci8"))  wire = VRT::FMT_CI8;
            else if (!strcmp(f, "ci12")) wire = VRT::FMT_CI12;
            else if (!strcmp(f, "ci16")) wire = VRT::FMT_CI16;
            else if (!strcmp(f, "cf32")) wire = VRT::FMT_CF32;
            else { fprintf(stderr, "unknown format: %s\n", f); return 1; }
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
    }

    if (tone == 0.0)
        tone = rate / 8.0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, dest.c_str(), &sa.sin_addr) != 1) {
        fprintf(stderr, "cannot parse address %s\n", dest.c_str());
        return 1;
    }
    if ((ntohl(sa.sin_addr.s_addr) >> 28) == 0xE) {
        int ttl = 8;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("connect");
        return 1;
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);

    const size_t prologue = 4 + (noSid ? 0 : 4) + 4 + 8;
    size_t perPacket = (mtu > prologue)
                     ? (mtu - prologue) / VRT::bytesPerSample(wire) : 0;
    while (perPacket > 0 && (Convert::payloadForSamples(perPacket, wire) & 3) != 0)
        perPacket--;
    if (perPacket == 0) {
        fprintf(stderr, "MTU %zu is too small for format %s\n",
                mtu, VRT::formatName(wire));
        return 1;
    }

    fprintf(stderr, "vita49-gen: %s:%u sid=0x%08x %s %.4g Msps %.4f MHz "
                    "%zu samples/packet%s\n",
            dest.c_str(), port, sid, VRT::formatName(wire),
            rate / 1e6, freq / 1e6, perPacket, little ? " little-endian" : "");

    std::vector<float> host(perPacket * 2);
    std::vector<uint8_t> payload(Convert::payloadForSamples(perPacket, wire));

    uint8_t count = 0, ctxCount = 0;
    long long sampleIndex = 0;
    long long deadline = monotonicNs();
    long long nextCtx = 0;
    long long sent = 0;
    const double twoPi = 6.283185307179586;

    while (g_run) {
        long long now = monotonicNs();

        if (ctxPerSec > 0.0 && now >= nextCtx) {
            VRT::ContextInfo info;
            info.haveSampleRate = true; info.sampleRate = rate;
            info.haveRfFreq     = true; info.rfFreq     = freq;
            info.haveBandwidth  = true; info.bandwidth  = rate * 0.8;
            info.haveFormat     = true; info.format     = wire;
            info.linkEfficient  = (wire == VRT::FMT_CI12);

            long long rt = realtimeNs();
            std::vector<uint8_t> pkt = VRT::buildContext(
                sid, ctxCount++, info,
                VRT::TSI_UTC, (uint32_t)(rt / 1000000000LL),
                VRT::TSF_REALTIME_PS, (uint64_t)(rt % 1000000000LL) * 1000ULL,
                little);
            if (send(fd, pkt.data(), pkt.size(), 0) < 0 && errno != ECONNREFUSED)
                perror("send context");
            nextCtx = now + (long long)(1e9 / ctxPerSec);
        }

        /* A complex exponential at the requested offset, so a receiver shows a
         * single line at a predictable place in the spectrum. */
        for (size_t i = 0; i < perPacket; i++) {
            double phase = twoPi * tone * (double)(sampleIndex + (long long)i) / rate;
            host[i * 2]     = 0.5f * (float)cos(phase);
            host[i * 2 + 1] = 0.5f * (float)sin(phase);
        }

        Convert::hostToWire((const uint8_t *)host.data(), Convert::HOST_CF32,
                            payload.data(), wire, little, perPacket);

        long long rt = realtimeNs();
        VRT::Builder b(little);
        b.begin(noSid ? VRT::PKT_SIGNAL_DATA_NO_SID : VRT::PKT_SIGNAL_DATA, count++);
        if (!noSid)
            b.setStreamId(sid);
        b.setTimestamp(VRT::TSI_UTC, (uint32_t)(rt / 1000000000LL),
                       VRT::TSF_REALTIME_PS,
                       (uint64_t)(rt % 1000000000LL) * 1000ULL);
        b.appendBytes(payload.data(), payload.size());
        const std::vector<uint8_t> &pkt = b.finish();

        if (send(fd, pkt.data(), pkt.size(), 0) < 0 && errno != ECONNREFUSED)
            perror("send data");

        sampleIndex += (long long)perPacket;
        sent++;
        if (limit > 0 && sent >= limit)
            break;

        deadline += (long long)((double)perPacket / rate * 1e9);
        long long slack = deadline - monotonicNs();
        if (slack > 0) {
            struct timespec ts;
            ts.tv_sec  = (time_t)(deadline / 1000000000LL);
            ts.tv_nsec = (long)(deadline % 1000000000LL);
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr);
        } else if (slack < -100000000LL) {
            deadline = monotonicNs();
        }
    }

    fprintf(stderr, "vita49-gen: sent %lld data packets\n", sent);
    close(fd);
    return 0;
}
