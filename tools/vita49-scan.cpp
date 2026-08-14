/*
 * vita49-scan: find VITA 49 streams and record them in the discovery cache.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Discovery.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s [options]\n"
"\n"
"Finds VITA 49 streams and records them so that SoapySDR device enumeration\n"
"can list them without sweeping the network every time.\n"
"\n"
"  -i IFACE     capture interface for the passive scan (default: any)\n"
"  -t MS        dwell time in milliseconds (default: 3000)\n"
"  -p LOW-HIGH  port range for the bind scan (default: 1024-65535)\n"
"  -w           probe only the well-known VITA 49 ports\n"
"  -e ADDR:PORT listen on one endpoint instead of scanning\n"
"  -m GROUP     also join this multicast group during a bind scan\n"
"  -b           skip the capture scan and bind ports directly\n"
"  -n           do not write the discovery cache\n"
"  -c           print the cache and exit\n"
"  -f FILE      replay a capture file instead of scanning\n"
"  -v           report capture and bind statistics\n"
"\n"
"The passive scan needs packet capture rights. Grant them once with:\n"
"  sudo setcap cap_net_raw,cap_net_admin+eip %s\n"
"Without them the bind scan is used, which only sees unicast traffic on\n"
"ports no other process holds.\n",
        argv0, argv0);
}

static void printStreams(const std::vector<Discovery::StreamInfo> &streams)
{
    if (streams.empty()) {
        printf("no VITA 49 streams found\n");
        return;
    }

    printf("%-16s %-6s %-10s %-6s %12s %14s %s\n",
           "DESTINATION", "PORT", "STREAM ID", "FORMAT", "RATE", "FREQ", "SOURCE");

    for (const auto &s : streams) {
        char sid[16] = "-";
        if (s.hasStreamId)
            snprintf(sid, sizeof(sid), "0x%08x", s.streamId);

        char rate[24] = "-";
        if (s.sampleRate > 0.0)
            snprintf(rate, sizeof(rate), "%.4g Msps", s.sampleRate / 1e6);
        else if (s.observedRate > 0.0)
            snprintf(rate, sizeof(rate), "~%.4g Msps", s.observedRate / 1e6);

        char freq[24] = "-";
        if (s.rfFreq > 0.0)
            snprintf(freq, sizeof(freq), "%.4f MHz", s.rfFreq / 1e6);

        printf("%-16s %-6u %-10s %-6s %12s %14s %s\n",
               s.dstAddr.empty() ? "0.0.0.0" : s.dstAddr.c_str(),
               s.dstPort, sid, VRT::formatName(s.format), rate, freq,
               s.srcAddr.empty() ? "-" : s.srcAddr.c_str());

        /* Dialect details only matter when they deviate from the spec, so they
         * are reported as a note rather than a column. */
        if (s.hdrSwap || s.dataSwap || s.vrlFramed) {
            printf("%-16s   note:", "");
            if (s.hdrSwap)   printf(" little-endian headers");
            if (s.dataSwap)  printf(" little-endian samples");
            if (s.vrlFramed) printf(" VRL framed");
            printf("\n");
        }
        if (!s.haveContext)
            printf("%-16s   note: no context packet seen, rate and frequency "
                   "are estimates\n", "");
    }

    printf("\nUse a stream with:\n");
    const Discovery::StreamInfo &s = streams.front();
    if (s.hasStreamId)
        printf("  SoapySDRUtil --probe=\"driver=vita49,addr=%s,port=%u,sid=0x%08x\"\n",
               s.dstAddr.empty() ? "0.0.0.0" : s.dstAddr.c_str(),
               s.dstPort, s.streamId);
    else
        printf("  SoapySDRUtil --probe=\"driver=vita49,addr=%s,port=%u\"\n",
               s.dstAddr.empty() ? "0.0.0.0" : s.dstAddr.c_str(), s.dstPort);
}

int main(int argc, char **argv)
{
    Discovery::ScanOptions opt;
    opt.dwellMs = 3000;

    std::string endpoint, pcapFile;
    bool writeCache = true;
    bool showCache  = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(a, "-i") && i + 1 < argc) {
            opt.iface = argv[++i];
        } else if (!strcmp(a, "-t") && i + 1 < argc) {
            opt.dwellMs = atoi(argv[++i]);
        } else if (!strcmp(a, "-p") && i + 1 < argc) {
            const char *r = argv[++i];
            const char *dash = strchr(r, '-');
            if (dash == nullptr) {
                fprintf(stderr, "port range must be LOW-HIGH\n");
                return 1;
            }
            opt.portLow  = (uint16_t)atoi(r);
            opt.portHigh = (uint16_t)atoi(dash + 1);
        } else if (!strcmp(a, "-w")) {
            opt.wellKnownOnly = true;
        } else if (!strcmp(a, "-e") && i + 1 < argc) {
            endpoint = argv[++i];
        } else if (!strcmp(a, "-m") && i + 1 < argc) {
            opt.mcastGroups.push_back(argv[++i]);
        } else if (!strcmp(a, "-b")) {
            opt.allowPcap = false;
        } else if (!strcmp(a, "-n")) {
            writeCache = false;
        } else if (!strcmp(a, "-f") && i + 1 < argc) {
            pcapFile = argv[++i];
        } else if (!strcmp(a, "-c")) {
            showCache = true;
        } else if (!strcmp(a, "-v")) {
            opt.verbose = true;
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
    }

    if (showCache) {
        printf("cache: %s\n\n", Discovery::cachePath().c_str());
        printStreams(Discovery::cacheLoad(0));
        return 0;
    }

    std::vector<Discovery::StreamInfo> streams;

    if (!pcapFile.empty()) {
        std::string err;
        if (!Discovery::scanPcapFile(pcapFile, streams, err)) {
            fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        fprintf(stderr, "replayed %s\n\n", pcapFile.c_str());
        if (writeCache) {
            std::string cerr;
            Discovery::cacheMerge(streams, cerr);
        }
    } else if (!endpoint.empty()) {
        std::string addr = "0.0.0.0";
        uint16_t port = 4991;
        size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos) {
            port = (uint16_t)atoi(endpoint.c_str());
        } else {
            addr = endpoint.substr(0, colon);
            port = (uint16_t)atoi(endpoint.c_str() + colon + 1);
        }

        fprintf(stderr, "listening on %s:%u for %d ms\n",
                addr.c_str(), port, opt.dwellMs);

        std::string err;
        if (!Discovery::probeEndpoint(addr, port, opt.dwellMs, streams, err)) {
            fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        if (writeCache) {
            std::string cerr;
            Discovery::cacheMerge(streams, cerr);
        }
    } else {
        std::string note;
        if (writeCache) {
            streams = Discovery::scanAuto(opt, note);
        } else {
            std::string err;
            if (!opt.allowPcap || !Discovery::scanPcap(opt, streams, err)) {
                if (!err.empty())
                    note = "capture unavailable (" + err + "); ";
                std::string berr;
                if (Discovery::scanBind(opt, streams, berr))
                    note += "bind scan";
                else
                    note += "bind scan failed: " + berr;
            } else {
                note = "capture scan";
            }
        }
        fprintf(stderr, "%s\n\n", note.c_str());
    }

    printStreams(streams);

    if (writeCache && !streams.empty())
        fprintf(stderr, "\ncached to %s\n", Discovery::cachePath().c_str());

    return streams.empty() ? 1 : 0;
}
