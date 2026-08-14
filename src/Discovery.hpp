/*
 * Discovery of VITA 49 streams on the network.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "VRT.hpp"

#include <cstdint>
#include <string>
#include <vector>

/**
 * @file Discovery.hpp
 * @brief Finding streams, and caching what was found.
 *
 * Two mechanisms see different things. A capture scan classifies every UDP
 * datagram reaching the host, including multicast and ports another process
 * holds, but needs CAP_NET_RAW. A bind scan needs no privileges but sees only
 * unicast traffic addressed to this host on ports nothing else has bound.
 */

namespace Discovery {

/**
 * @brief One stream as observed on the wire.
 *
 * A stream is identified by destination address, UDP port and stream
 * identifier together, because one port commonly carries several streams.
 */
struct StreamInfo {
    std::string srcAddr;           /**< Sender address. */
    std::string dstAddr;           /**< Destination address, or the bound wildcard. */
    uint16_t    dstPort     = 0;   /**< Destination UDP port. */
    uint32_t    streamId    = 0;   /**< VRT stream identifier. */
    bool        hasStreamId = false; /**< Packet class carries a stream identifier. */

    /* Header and sample byte order are tracked separately because sources set
     * them independently. Only the header order can be detected. */
    bool        hdrSwap   = false; /**< Header words are little-endian. */
    bool        dataSwap  = false; /**< Payload items are little-endian. */
    bool        vrlFramed = false; /**< Packets arrive inside VRL frames. */

    bool        haveContext = false;              /**< A context packet was decoded. */
    VRT::SampleFormat format = VRT::FMT_UNKNOWN;  /**< Payload format. */
    double      sampleRate  = 0.0;                /**< Hz, from context. */
    double      rfFreq      = 0.0;                /**< Hz, from context. */
    double      bandwidth   = 0.0;                /**< Hz, from context. */

    uint64_t    dataPackets    = 0;   /**< Signal data packets seen. */
    uint64_t    contextPackets = 0;   /**< Context packets seen. */
    uint64_t    payloadBytes   = 0;   /**< Payload bytes accumulated. */
    unsigned    seqRun         = 0;   /**< Consecutive in-order packet counts. */
    double      observedRate   = 0.0; /**< Complex samples/s inferred from traffic. */
    int64_t     lastSeen       = 0;   /**< Unix seconds. */

    /** @brief Result of a liveness check. Runtime only, never cached. */
    enum Liveness {
        LIVE_UNKNOWN = 0, /**< Not checked. */
        LIVE_STREAMING,   /**< Packets arriving now. */
        LIVE_IDLE,        /**< Port free and silent. */
        LIVE_BUSY,        /**< Another process holds the port. */
    };
    Liveness liveness = LIVE_UNKNOWN;

    /** @brief Identity as "address:port/streamid". */
    std::string key() const;

    /** @brief Human-readable description for a device list. */
    std::string label() const;
};

/** @brief Ports a quick scan tries first. */
extern const uint16_t kWellKnownPorts[];

/** @brief Number of entries in kWellKnownPorts. */
extern const size_t kWellKnownPortCount;

/** @brief Parameters common to both scan mechanisms. */
struct ScanOptions {
    std::string iface         = "any";   /**< Capture interface. */
    int         dwellMs       = 2500;    /**< Listening window. */
    uint16_t    portLow       = 1024;    /**< First port of the bind range. */
    uint16_t    portHigh      = 65535;   /**< Last port of the bind range. */
    bool        wellKnownOnly = false;   /**< Ignore the range, use kWellKnownPorts. */
    int         batchSize     = 512;     /**< Sockets bound per pass. */
    bool        allowPcap     = true;    /**< Permit the capture scan. */
    bool        allowBind     = true;    /**< Permit the bind scan. */
    bool        verbose       = false;   /**< Report scan statistics. */
    std::vector<std::string> mcastGroups; /**< Extra groups to join while binding. */
};

/**
 * @brief Scan by capturing traffic.
 * @param opt Scan parameters; the port range is not used.
 * @param[out] out Streams found, appended.
 * @param[out] err Reason the capture could not be opened.
 * @return False if capture is unavailable, typically for lack of CAP_NET_RAW.
 */
bool scanPcap(const ScanOptions &opt, std::vector<StreamInfo> &out, std::string &err);

/**
 * @brief Scan by binding ports.
 * @param opt Scan parameters.
 * @param[out] out Streams found, appended.
 * @param[out] err Reason no port could be bound.
 * @return False if no port in the range could be bound.
 */
bool scanBind(const ScanOptions &opt, std::vector<StreamInfo> &out, std::string &err);

/**
 * @brief Replay a capture file through the classifier.
 * @param path Capture file.
 * @param[out] out Streams found, appended.
 * @param[out] err Reason the file could not be read.
 * @return False if the file could not be opened.
 */
bool scanPcapFile(const std::string &path, std::vector<StreamInfo> &out,
                  std::string &err);

/**
 * @brief Listen on one endpoint and report the streams seen.
 *
 * The only method that works before a source has started, and the fastest when
 * the endpoint is already known.
 *
 * @param bindAddr Address to bind, or a multicast group to join.
 * @param port UDP port.
 * @param dwellMs Listening window.
 * @param[out] out Streams found, appended.
 * @param[out] err Reason the socket could not be opened.
 * @return False if the endpoint could not be opened.
 */
bool probeEndpoint(const std::string &bindAddr, uint16_t port, int dwellMs,
                   std::vector<StreamInfo> &out, std::string &err);

/**
 * @brief Scan using capture if permitted, binding otherwise, and update the cache.
 * @param opt Scan parameters.
 * @param[out] note Which mechanism ran, for logging.
 * @return Streams found.
 */
std::vector<StreamInfo> scanAuto(const ScanOptions &opt, std::string &note);

/**
 * @brief Re-check cached entries against the network.
 *
 * The cache records what was true when it was written. A short dwell on those
 * endpoints separates streams still running from ones that have stopped; a
 * port another process holds counts as in use rather than dead.
 *
 * @param[in,out] entries Entries to check; liveness and metadata are updated.
 * @param dwellMs Listening window.
 */
void verifyLiveness(std::vector<StreamInfo> &entries, int dwellMs);

/**
 * @brief Extract the UDP payload from a captured link-layer frame.
 *
 * Exposed so that tools read capture files exactly as the scanner does.
 *
 * @param linkType libpcap link type.
 * @param frame Frame bytes.
 * @param caplen Bytes captured.
 * @param[out] srcAddr Source address.
 * @param[out] dstAddr Destination address.
 * @param[out] dstPort Destination port.
 * @param[out] payload Payload start within @p frame.
 * @param[out] payloadLen Payload length.
 * @return False for anything that is not IPv4 or IPv6 UDP.
 */
bool extractUdp(int linkType, const uint8_t *frame, size_t caplen,
                std::string *srcAddr, std::string *dstAddr, uint16_t *dstPort,
                const uint8_t **payload, size_t *payloadLen);

/** @name Cache of previously discovered streams. */
/**@{*/

/** @brief Path of the cache file. */
std::string cachePath();

/**
 * @brief Read the cache.
 * @param maxAgeSec Drop entries older than this; 0 keeps all.
 * @return Cached entries.
 */
std::vector<StreamInfo> cacheLoad(int maxAgeSec);

/**
 * @brief Replace the cache.
 * @param streams Entries to write.
 * @param[out] err Reason the write failed.
 * @return False on write failure.
 */
bool cacheStore(const std::vector<StreamInfo> &streams, std::string &err);

/**
 * @brief Merge new observations into the cache, keeping entries not seen.
 * @param fresh Newly observed entries.
 * @param[out] err Reason the write failed.
 * @return False on write failure.
 */
bool cacheMerge(const std::vector<StreamInfo> &fresh, std::string &err);

/**@}*/

/**
 * @brief Classify one datagram, creating or updating its stream record.
 *
 * Shared by every scan mechanism so they agree on what counts as a stream.
 *
 * @param[in,out] table Records accumulated so far.
 * @param srcAddr Sender address.
 * @param dstAddr Destination address.
 * @param dstPort Destination port.
 * @param pkt Datagram bytes.
 * @param len Datagram length.
 */
void classify(std::vector<StreamInfo> &table,
              const std::string &srcAddr, const std::string &dstAddr,
              uint16_t dstPort, const uint8_t *pkt, size_t len);

/**
 * @brief Drop records that were never convincing.
 *
 * A record is kept when a context packet decoded, or when at least three
 * consecutive data packets stepped the packet counter by one.
 *
 * @param[in,out] table Records to filter.
 */
void prune(std::vector<StreamInfo> &table);

} /* namespace Discovery */
