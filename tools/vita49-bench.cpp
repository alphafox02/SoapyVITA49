/*
 * vita49-bench: measure sustained receive throughput.
 *
 * Streams from one or more endpoints and discards the samples, leaving only
 * the network, the kernel and this driver in the path. Reports sequence gaps
 * and application drops separately, since they have different causes and
 * different remedies.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <time.h>

#include <SoapySDR/Device.hpp>
#include <SoapySDR/Formats.hpp>

namespace {

double nowSec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

struct Result {
    unsigned long long samples = 0;
    double   elapsed  = 0.0;
    double   srcRate  = 0.0;
    unsigned long long gaps = 0, dropped = 0, packets = 0;
    std::string error;
};

/* Pull the named counter out of the driver's stats string. */
unsigned long long statValue(const std::string &stats, const std::string &key)
{
    size_t p = stats.find(key + "=");
    if (p == std::string::npos)
        return 0;
    return strtoull(stats.c_str() + p + key.size() + 1, nullptr, 10);
}

void worker(const std::string &addr, uint16_t port, const std::string &format,
            double seconds, size_t chunk, const std::string &rcvbuf,
            const std::string &buffers, Result *out)
{
    try {
        SoapySDR::Kwargs args;
        args["driver"]  = "vita49";
        args["addr"]    = addr;
        args["port"]    = std::to_string(port);
        args["rcvbuf"]  = rcvbuf;
        args["buffers"] = buffers;
        args["control"] = "off";     /* no probe delay in a benchmark */

        SoapySDR::Device *dev = SoapySDR::Device::make(args);
        SoapySDR::Stream *st = dev->setupStream(SOAPY_SDR_RX, format);
        dev->activateStream(st);

        size_t elemSize = (format == SOAPY_SDR_CF32) ? 8 :
                          (format == SOAPY_SDR_CS16) ? 4 : 2;
        std::vector<uint8_t> buf(chunk * elemSize);
        void *buffs[1] = { buf.data() };

        double t0 = nowSec();
        unsigned long long n = 0;
        while (nowSec() - t0 < seconds) {
            int flags = 0;
            long long timeNs = 0;
            int r = dev->readStream(st, buffs, chunk, flags, timeNs, 200000);
            if (r > 0)
                n += (unsigned long long)r;
        }
        out->elapsed = nowSec() - t0;
        out->samples = n;
        out->srcRate = dev->getSampleRate(SOAPY_SDR_RX, 0);

        std::string stats = dev->readSetting("stats");
        out->gaps    = statValue(stats, "gaps");
        out->dropped = statValue(stats, "dropped");
        out->packets = statValue(stats, "packets");

        dev->deactivateStream(st);
        dev->closeStream(st);
        SoapySDR::Device::unmake(dev);
    } catch (const std::exception &e) {
        out->error = e.what();
    }
}

void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s -p PORT[,PORT...] [options]\n"
"\n"
"Streams from one or more endpoints and discards the samples, leaving only\n"
"the network, the kernel and this driver in the path.\n"
"\n"
"  -a ADDR       bind address (default: 0.0.0.0)\n"
"  -p PORTS      comma-separated list of ports\n"
"  -F FORMAT     CS16, CF32 or CS8 (default: CS16, the native format)\n"
"  -t SECONDS    run time (default: 8)\n"
"  -c SAMPLES    samples per readStream call (default: 32768)\n"
"  -r BYTES      socket receive buffer to request (default: 134217728)\n"
"  -b BLOCKS     queued packets per channel (default: 2048)\n",
        argv0);
}

} /* anonymous namespace */

int main(int argc, char **argv)
{
    std::string addr = "0.0.0.0", format = SOAPY_SDR_CS16;
    std::string rcvbuf = "134217728", buffers = "2048";
    std::vector<uint16_t> ports;
    double seconds = 8.0;
    size_t chunk = 32768;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-a") && i + 1 < argc) addr = argv[++i];
        else if (!strcmp(a, "-F") && i + 1 < argc) format = argv[++i];
        else if (!strcmp(a, "-t") && i + 1 < argc) seconds = atof(argv[++i]);
        else if (!strcmp(a, "-c") && i + 1 < argc) chunk = (size_t)atol(argv[++i]);
        else if (!strcmp(a, "-r") && i + 1 < argc) rcvbuf = argv[++i];
        else if (!strcmp(a, "-b") && i + 1 < argc) buffers = argv[++i];
        else if (!strcmp(a, "-p") && i + 1 < argc) {
            char *list = strdup(argv[++i]);
            for (char *tok = strtok(list, ","); tok; tok = strtok(nullptr, ","))
                ports.push_back((uint16_t)atoi(tok));
            free(list);
        } else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 1; }
    }

    if (ports.empty()) { usage(argv[0]); return 1; }

    fprintf(stderr, "streaming %zu endpoint(s) as %s for %.0f s\n\n",
            ports.size(), format.c_str(), seconds);

    std::vector<Result> results(ports.size());
    std::vector<std::thread> threads;
    for (size_t i = 0; i < ports.size(); i++)
        threads.emplace_back(worker, addr, ports[i], format, seconds, chunk,
                             rcvbuf, buffers, &results[i]);
    for (auto &t : threads)
        t.join();

    double totalGot = 0, totalSrc = 0;
    unsigned long long totalGaps = 0, totalDropped = 0;

    printf("%-7s %12s %12s %8s %8s %10s\n",
           "PORT", "DELIVERED", "SOURCE", "OF SRC", "GAPS", "APP DROPS");

    for (size_t i = 0; i < ports.size(); i++) {
        const Result &r = results[i];
        if (!r.error.empty()) {
            printf("%-7u  error: %s\n", ports[i], r.error.c_str());
            continue;
        }
        double got = (r.elapsed > 0) ? (double)r.samples / r.elapsed / 1e6 : 0.0;
        double src = r.srcRate / 1e6;
        totalGot += got;
        totalSrc += src;
        totalGaps += r.gaps;
        totalDropped += r.dropped;

        printf("%-7u %9.2f Ms %9.2f Ms %7.1f%% %8llu %10llu\n",
               ports[i], got, src, (src > 0) ? 100.0 * got / src : 0.0,
               r.gaps, r.dropped);
    }

    size_t elemBytes = (format == SOAPY_SDR_CF32) ? 8 :
                       (format == SOAPY_SDR_CS16) ? 4 : 2;
    printf("\naggregate %.2f of %.2f Msps, %.0f MB/s delivered to the application\n",
           totalGot, totalSrc, totalGot * 1e6 * (double)elemBytes / 1e6);
    printf("wire rate %.2f Gb/s at 4 bytes per complex sample\n",
           totalSrc * 4 * 8 / 1000.0);

    /* The counters separate loss before the driver from loss inside it. */
    if (totalGaps > 0)
        printf("\n%llu sequence gap(s): datagrams were lost before the driver saw\n"
               "them. Raise net.core.rmem_max and the interface receive ring.\n",
               totalGaps);
    else
        printf("\nNo sequence gaps.\n");

    if (totalDropped > 0)
        printf("%llu block(s) dropped because readStream was not called often\n"
               "enough. Read larger chunks, use CS16, or do less work per sample.\n",
               totalDropped);
    else
        printf("No application drops: the consumer kept up with the source.\n");

    return 0;
}
