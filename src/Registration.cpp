/*
 * Module registration and device enumeration.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "SoapyVITA49.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <cstring>

#include <SoapySDR/Logger.hpp>
#include <SoapySDR/Registry.hpp>

namespace {

std::string argOr(const SoapySDR::Kwargs &args, const std::string &key,
                  const std::string &fallback)
{
    auto it = args.find(key);
    return (it == args.end()) ? fallback : it->second;
}

bool argFlag(const SoapySDR::Kwargs &args, const std::string &key, bool fallback)
{
    auto it = args.find(key);
    if (it == args.end())
        return fallback;
    const std::string &v = it->second;
    return !(v == "0" || v == "false" || v == "no" || v == "off");
}

/* Turn one discovered stream into the argument set that identifies it. Every
 * key here round-trips into make(), so a device selected from a list opens
 * exactly the stream that was enumerated.
 *
 * Anything the caller stated explicitly is preserved: SoapySDR builds the
 * final make() arguments from an enumeration result, so a discovered value
 * emitted here would otherwise silently replace what was asked for, and an
 * override such as data_endian= would appear to do nothing. */
SoapySDR::Kwargs streamToKwargs(const Discovery::StreamInfo &s,
                                const SoapySDR::Kwargs &caller)
{
    SoapySDR::Kwargs k;
    k["driver"] = "vita49";
    k["label"]  = s.label();
    k["addr"]   = s.dstAddr.empty() ? "0.0.0.0" : s.dstAddr;
    k["port"]   = std::to_string(s.dstPort);

    /* Applications identify devices by serial as often as by label, and one
     * that keys on serial alone collapses every stream into a single entry
     * when the field is absent. Endpoint and stream identifier together are
     * unique and stable across enumerations. */
    k["serial"] = s.key();

    if (s.hasStreamId) {
        char sid[16];
        snprintf(sid, sizeof(sid), "0x%08x", s.streamId);
        k["sid"] = sid;
    } else {
        k["sid"] = "none";
    }

    if (s.format != VRT::FMT_UNKNOWN)
        k["format"] = VRT::formatName(s.format);
    if (s.sampleRate > 0.0)
        k["rate"] = std::to_string((long long)s.sampleRate);
    if (s.rfFreq > 0.0)
        k["freq"] = std::to_string((long long)s.rfFreq);
    if (s.bandwidth > 0.0)
        k["bandwidth"] = std::to_string((long long)s.bandwidth);

    k["hdr_endian"]  = s.hdrSwap  ? "little" : "big";
    k["data_endian"] = s.dataSwap ? "little" : "big";
    if (s.vrlFramed)
        k["vrl"] = "1";
    if (!s.srcAddr.empty() && s.srcAddr != "-")
        k["source"] = s.srcAddr;

    for (const auto &kv : caller)
        k[kv.first] = kv.second;

    return k;
}

/* Cached entries older than this are not offered as devices. A stream that
 * has been quiet for a day is almost certainly gone. */
const int kCacheMaxAgeSec = 24 * 60 * 60;

/* The cache records what was true when it was written, so check the entries
 * against the network before offering them. Entries that have stopped are kept
 * but labelled, because a source that is merely not started yet is still worth
 * offering; verify=0 skips the check for a host that enumerates constantly. */
void verifyCached(std::vector<Discovery::StreamInfo> &streams,
                  const SoapySDR::Kwargs &args)
{
    if (streams.empty() || !argFlag(args, "verify", true))
        return;

    int dwell = atoi(argOr(args, "verify_ms", "400").c_str());
    Discovery::verifyLiveness(streams, dwell);

    if (argFlag(args, "hide_idle", false)) {
        streams.erase(std::remove_if(streams.begin(), streams.end(),
            [](const Discovery::StreamInfo &s) {
                return s.liveness == Discovery::StreamInfo::LIVE_IDLE;
            }), streams.end());
    }
}

} /* anonymous namespace */

/* Enumeration order: an explicit addr/port needs no discovery at all, then the
 * cache, then a sweep if the cache is empty. Hosts call this whenever they
 * refresh a device list, so the cache is what keeps it quick. */
SoapySDR::KwargsList SoapyVITA49::find(const SoapySDR::Kwargs &args)
{
    SoapySDR::KwargsList results;

    /* Do not answer enumerations aimed at a different driver. */
    auto drv = args.find("driver");
    if (drv != args.end() && drv->second != "vita49")
        return results;

    const std::string scanMode = argOr(args, "scan", "cache");
    std::vector<Discovery::StreamInfo> streams;

    if (args.count("addr") || args.count("port")) {
        std::string addr = argOr(args, "addr", "0.0.0.0");
        uint16_t port = (uint16_t)strtoul(argOr(args, "port", "4991").c_str(),
                                          nullptr, 10);

        if (argFlag(args, "probe", true)) {
            int dwell = atoi(argOr(args, "dwell", "1500").c_str());
            std::string err;
            if (!Discovery::probeEndpoint(addr, port, dwell, streams, err))
                SoapySDR::logf(SOAPY_SDR_WARNING, "vita49: %s", err.c_str());
        }

        /* Offer the endpoint even when nothing was heard: the source may not
         * have started yet, and a user who names an address means it. */
        if (streams.empty()) {
            Discovery::StreamInfo s;
            s.dstAddr     = addr;
            s.dstPort     = port;
            s.hasStreamId = args.count("sid") && argOr(args, "sid", "") != "none";
            if (s.hasStreamId)
                s.streamId = (uint32_t)strtoul(argOr(args, "sid", "0").c_str(),
                                               nullptr, 0);
            streams.push_back(s);
        }
    } else if (scanMode == "off") {
        streams = Discovery::cacheLoad(kCacheMaxAgeSec);
        verifyCached(streams, args);
    } else if (scanMode == "full" || scanMode == "quick") {
        Discovery::ScanOptions opt;
        opt.iface   = argOr(args, "iface", "any");
        opt.verbose = argFlag(args, "verbose", false);
        if (scanMode == "quick") {
            opt.dwellMs       = atoi(argOr(args, "dwell", "800").c_str());
            opt.wellKnownOnly = true;
        } else {
            opt.dwellMs  = atoi(argOr(args, "dwell", "3000").c_str());
            opt.portLow  = (uint16_t)strtoul(
                argOr(args, "port_low", "1024").c_str(), nullptr, 10);
            opt.portHigh = (uint16_t)strtoul(
                argOr(args, "port_high", "65535").c_str(), nullptr, 10);
        }
        std::string note;
        streams = Discovery::scanAuto(opt, note);
        SoapySDR::logf(SOAPY_SDR_INFO, "vita49: %s found %zu stream(s)",
                       note.c_str(), streams.size());
    } else {
        streams = Discovery::cacheLoad(kCacheMaxAgeSec);
        verifyCached(streams, args);
        if (streams.empty()) {
            /* Nothing cached, so sweep the whole unprivileged range rather
             * than guess at vendor defaults. Binding all 64512 ports takes one
             * pass and the dwell dominates, so this costs a little over a
             * second and only happens when the cache is empty. */
            Discovery::ScanOptions opt;
            opt.iface    = argOr(args, "iface", "any");
            opt.dwellMs  = atoi(argOr(args, "dwell", "1200").c_str());
            opt.portLow  = 1024;
            opt.portHigh = 65535;
            std::string note;
            streams = Discovery::scanAuto(opt, note);
        }
    }

    /* sid=all is one multi-channel device, not one per stream, and must be a
     * single entry: SoapySDR fills missing make() arguments from the first
     * result, so per-stream entries would overwrite sid=all with a concrete
     * ID and collapse it to one channel. */
    const std::string sidArg = argOr(args, "sid", "");
    if (sidArg == "all") {
        std::map<std::string, Discovery::StreamInfo> byEndpoint;
        for (const auto &s : streams) {
            std::string ep = s.dstAddr + ":" + std::to_string(s.dstPort);
            if (byEndpoint.find(ep) == byEndpoint.end())
                byEndpoint[ep] = s;
        }
        for (const auto &kv : byEndpoint) {
            SoapySDR::Kwargs k = streamToKwargs(kv.second, args);
            k["sid"] = "all";
            /* Per-stream rate, frequency and format do not describe a device
             * whose channels may differ, so they are left for the channels
             * themselves to discover. */
            k.erase("rate");
            k.erase("freq");
            k.erase("bandwidth");
            k.erase("format");
            k["label"] = "VITA-49 " + kv.first + " all streams";
            results.push_back(k);
        }
        return results;
    }

    /* Apply any filters the caller supplied so that a fully-specified request
     * resolves to exactly one device. */
    for (const auto &s : streams) {
        if (args.count("sid")) {
            const std::string want = args.at("sid");
            /* "all", "any" and "none" select rather than filter: they ask for
             * every stream on the endpoint, so no stream ID comparison
             * applies. Treating them as a number filters everything out. */
            if (want != "none" && want != "any" && want != "all") {
                uint32_t sid = (uint32_t)strtoul(want.c_str(), nullptr, 0);
                if (!s.hasStreamId || s.streamId != sid)
                    continue;
            }
        }
        if (args.count("port") &&
            s.dstPort != (uint16_t)strtoul(args.at("port").c_str(), nullptr, 10))
            continue;

        results.push_back(streamToKwargs(s, args));
    }

    return results;
}

SoapySDR::Device *SoapyVITA49::make(const SoapySDR::Kwargs &args)
{
    return new SoapyVITA49(args);
}

/* Module entry point: registers the driver with SoapySDR at load time. */
static SoapySDR::Registry registerVITA49("vita49", &SoapyVITA49::find,
                                         &SoapyVITA49::make, SOAPY_SDR_ABI_VERSION);
