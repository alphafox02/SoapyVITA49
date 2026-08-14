/*
 * VRT packet layer for VITA 49.0 and VITA 49.2.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * @file VRT.hpp
 * @brief Parsing and construction of VRT packets.
 *
 * Section references are to ANSI/VITA 49.0-2015 unless a function names
 * VITA 49.2 explicitly. Multi-byte fields are big-endian on the wire; every
 * entry point takes a @c swap flag for sources that emit little-endian words.
 */

namespace VRT {

/** @brief Packet type, header word 0 bits 31:28 (Table 6.1.1-1). */
enum PacketType {
    PKT_SIGNAL_DATA_NO_SID = 0x0, /**< Signal data, no stream identifier. */
    PKT_SIGNAL_DATA        = 0x1, /**< Signal data with stream identifier. */
    PKT_EXT_DATA_NO_SID    = 0x2, /**< Extension data, no stream identifier. */
    PKT_EXT_DATA           = 0x3, /**< Extension data with stream identifier. */
    PKT_IF_CONTEXT         = 0x4, /**< IF context. */
    PKT_EXT_CONTEXT        = 0x5, /**< Extension context. */
    PKT_COMMAND            = 0x6, /**< Command (VITA 49.2). */
    PKT_EXT_COMMAND        = 0x7, /**< Extension command (VITA 49.2). */
};

/** @brief Integer timestamp interpretation, header bits 23:22. */
enum TSI {
    TSI_NONE  = 0, /**< No integer timestamp. */
    TSI_UTC   = 1, /**< Seconds since the UTC epoch. */
    TSI_GPS   = 2, /**< Seconds since the GPS epoch. */
    TSI_OTHER = 3, /**< Source-defined. */
};

/** @brief Fractional timestamp interpretation, header bits 21:20. */
enum TSF {
    TSF_NONE         = 0, /**< No fractional timestamp. */
    TSF_SAMPLE_COUNT = 1, /**< Samples elapsed within the second. */
    TSF_REALTIME_PS  = 2, /**< Picoseconds within the second. */
    TSF_FREE_RUNNING = 3, /**< Free-running sample count. */
};

/** @brief Magic word opening a VRL frame, "VRLP" (section 5). */
static const uint32_t VRL_MAGIC = 0x56524C50;

/** @brief Magic word closing a VRL frame, "VEND". */
static const uint32_t VRL_END = 0x56454E44;

/** @brief Complex sample formats this module can carry. */
enum SampleFormat {
    FMT_UNKNOWN = 0, /**< Not yet determined, or unsupported. */
    FMT_CI8,         /**< Signed 8-bit. */
    FMT_CI12,        /**< Signed 12-bit, link-efficient packed. */
    FMT_CI16,        /**< Signed 16-bit. */
    FMT_CF32,        /**< IEEE-754 single precision. */
};

/**
 * @brief Short name of a sample format.
 * @param f Format to name.
 * @return Static string such as "ci16", or "unknown".
 */
const char *formatName(SampleFormat f);

/**
 * @brief Wire size of one complex sample.
 * @param f Format to measure.
 * @return Bytes per complex sample, or 0 if the format is unknown.
 */
size_t bytesPerSample(SampleFormat f);

/**
 * @brief CIF0 indicator bits (section 7.1.5).
 *
 * Listed most significant first, which is also the order the corresponding
 * fields appear in the packet body.
 */
enum CIF0Bit {
    CIF0_CHANGE_IND       = 1u << 31, /**< Context field change; occupies no field. */
    CIF0_REF_POINT_ID     = 1u << 30,
    CIF0_BANDWIDTH        = 1u << 29,
    CIF0_IF_REF_FREQ      = 1u << 28,
    CIF0_RF_REF_FREQ      = 1u << 27,
    CIF0_RF_FREQ_OFFSET   = 1u << 26,
    CIF0_IF_BAND_OFFSET   = 1u << 25,
    CIF0_REF_LEVEL        = 1u << 24,
    CIF0_GAIN             = 1u << 23,
    CIF0_OVER_RANGE_COUNT = 1u << 22,
    CIF0_SAMPLE_RATE      = 1u << 21,
    CIF0_TS_ADJUSTMENT    = 1u << 20,
    CIF0_TS_CALIB_TIME    = 1u << 19,
    CIF0_TEMPERATURE      = 1u << 18,
    CIF0_DEVICE_ID        = 1u << 17,
    CIF0_STATE_EVENT      = 1u << 16,
    CIF0_DATA_FORMAT      = 1u << 15,
    CIF0_FORMATTED_GPS    = 1u << 14,
    CIF0_FORMATTED_INS    = 1u << 13,
    CIF0_ECEF_EPHEMERIS   = 1u << 12,
    CIF0_REL_EPHEMERIS    = 1u << 11,
    CIF0_EPHEMERIS_REF_ID = 1u << 10,
    CIF0_GPS_ASCII        = 1u << 9,  /**< Variable length. */
    CIF0_CONTEXT_ASSOC    = 1u << 8,  /**< Variable length. */
    CIF0_CIF7_ENABLE      = 1u << 7,  /**< VITA 49.2. */
    CIF0_CIF3_ENABLE      = 1u << 3,  /**< VITA 49.2. */
    CIF0_CIF2_ENABLE      = 1u << 2,  /**< VITA 49.2. */
    CIF0_CIF1_ENABLE      = 1u << 1,  /**< VITA 49.2. */
};

/** @name Fixed-point radix points used by the CIF0 fields decoded here. */
/**@{*/
static const int RADIX_FREQ_HZ   = 20; /**< 64-bit frequency, Hz. */
static const int RADIX_SAMP_RATE = 20; /**< 64-bit sample rate, Hz. */
static const int RADIX_GAIN_DB   = 7;  /**< 16-bit gain, dB. */
static const int RADIX_REF_LEVEL = 7;  /**< 16-bit reference level, dBm. */
static const int RADIX_BANDWIDTH = 20; /**< 64-bit bandwidth, Hz. */
static const int RADIX_TEMP_C    = 6;  /**< 16-bit temperature, degrees C. */
/**@}*/

/** @brief Decoded packet header, common to every packet class. */
struct Header {
    PacketType type;          /**< Packet type from bits 31:28. */
    bool       hasClassId;    /**< Class identifier present. */
    bool       hasTrailer;    /**< Trailer present; data packets only. */
    bool       hasStreamId;   /**< Stream identifier present. */
    TSI        tsi;           /**< Integer timestamp interpretation. */
    TSF        tsf;           /**< Fractional timestamp interpretation. */
    uint8_t    count;         /**< Modulo-16 packet counter. */
    size_t     sizeWords;     /**< Declared packet size in 32-bit words. */

    uint32_t   streamId;      /**< Stream identifier, 0 when absent. */
    uint64_t   classId;       /**< OUI in the upper word, class codes in the lower. */
    uint32_t   tsInt;         /**< Integer timestamp, 0 when absent. */
    uint64_t   tsFrac;        /**< Fractional timestamp, 0 when absent. */

    size_t     payloadOffset; /**< Payload offset in bytes from the packet start. */
    size_t     payloadBytes;  /**< Payload length in bytes, excluding any trailer. */
};

/**
 * @brief Decoded signal data trailer (section 6.1.7).
 *
 * The trailer pairs an enable at bit N+12 with an indicator at bit N. An
 * indicator whose enable is clear carries no meaning, so each field is
 * reported as a have/value pair: "not reported" and "reported false" are
 * different answers.
 */
struct Trailer {
    bool haveCalibratedTime = false, calibratedTime = false;
    bool haveValidData      = false, validData      = false;
    bool haveReferenceLock  = false, referenceLock  = false;
    bool haveAgc            = false, agc            = false;
    bool haveDetectedSignal = false, detectedSignal = false;
    bool haveSpectralInv    = false, spectralInv    = false;
    bool haveOverRange      = false, overRange      = false;
    bool haveSampleLoss     = false, sampleLoss     = false;

    bool     haveContextCount = false; /**< Associated context packet count present. */
    unsigned contextCount     = 0;     /**< Associated context packet count. */
};

/**
 * @brief Metadata recovered from a context packet or command acknowledgement.
 *
 * Every field is optional; a source may send any subset in any given packet.
 * The matching have flag indicates which members were populated.
 */
struct ContextInfo {
    bool     haveSampleRate  = false;
    bool     haveRfFreq      = false;
    bool     haveIfFreq      = false;
    bool     haveBandwidth   = false;
    bool     haveGain        = false;
    bool     haveRefLevel    = false;
    bool     haveFormat      = false;
    bool     haveOverRange   = false;
    bool     haveTemperature = false;

    double   sampleRate   = 0.0; /**< Hz. */
    double   rfFreq       = 0.0; /**< RF reference frequency, Hz. */
    double   ifFreq       = 0.0; /**< IF reference frequency, Hz. */
    double   bandwidth    = 0.0; /**< Hz. */
    double   gainStage1   = 0.0; /**< dB. */
    double   gainStage2   = 0.0; /**< dB. */
    double   refLevel     = 0.0; /**< dBm. */
    double   temperature  = 0.0; /**< Degrees C. */
    uint32_t overRange    = 0;   /**< Over-range sample count. */

    SampleFormat format   = FMT_UNKNOWN; /**< Payload format. */
    bool     linkEfficient = false;      /**< Payload format word 1 bit 31. */
    unsigned itemSizeBits  = 0;          /**< Data item size in bits. */
    unsigned packingBits   = 0;          /**< Item packing field size in bits. */

    bool     haveDeviceId = false; /**< Device Identifier field was present. */
    uint32_t deviceOui    = 0;     /**< Manufacturer OUI, 24 bits. */
    uint16_t deviceCode   = 0;     /**< Manufacturer-assigned device code. */

    uint32_t streamId        = 0;     /**< Stream the packet described. */
    bool     changeIndicator = false; /**< CIF0 bit 31 was set. */
};

/**
 * @brief Locate the VRT packet inside a datagram, skipping any VRL frame.
 * @param pkt Datagram bytes.
 * @param len Datagram length in bytes.
 * @param[out] vrtLen Usable VRT length in bytes.
 * @return Byte offset of the VRT packet; 0 when no VRL frame is present.
 */
size_t vrlStrip(const uint8_t *pkt, size_t len, size_t *vrtLen);

/**
 * @brief Decode a packet header and locate its payload.
 * @param vrt Start of the VRT packet.
 * @param len Bytes available from @p vrt.
 * @param swap Read 32-bit words little-endian.
 * @param[out] out Decoded header.
 * @return False if the packet is truncated or declares a size that does not fit.
 */
bool parseHeader(const uint8_t *vrt, size_t len, bool swap, Header *out);

/**
 * @brief Decode the fields of a context packet.
 * @param vrt Start of the VRT packet.
 * @param len Bytes available from @p vrt.
 * @param swap Read 32-bit words little-endian.
 * @param[out] out Fields found, accumulated into the caller's structure.
 * @return False if the packet is not a context packet or the field walk
 *         overruns the declared packet size.
 */
bool parseContext(const uint8_t *vrt, size_t len, bool swap, ContextInfo *out);

/**
 * @brief Walk a CIF0 indicator word and the field body that follows it.
 *
 * Context packets and VITA 49.2 command packets encode fields identically and
 * differ only in the words preceding CIF0, so both use this walker.
 *
 * @param vrt Start of the VRT packet.
 * @param sizeWords Declared packet size in 32-bit words.
 * @param startWord Word index of the CIF0 indicator.
 * @param swap Read 32-bit words little-endian.
 * @param[out] out Fields found, accumulated into the caller's structure.
 * @return False if the field walk overruns the declared packet size.
 */
bool parseCIF0(const uint8_t *vrt, size_t sizeWords, size_t startWord,
               bool swap, ContextInfo *out);

/**
 * @brief Decode the two-word Data Packet Payload Format field (section 7.1.5.18).
 * @param w1 First field word.
 * @param w2 Second field word.
 * @param[out] out Receives format, packing and item size.
 * @return False for formats without a complex cartesian equivalent.
 */
bool parsePayloadFormat(uint32_t w1, uint32_t w2, ContextInfo *out);

/**
 * @brief Decode the trailer of a signal data packet.
 * @param vrt Start of the VRT packet.
 * @param h Header already decoded from the same packet.
 * @param swap Read 32-bit words little-endian.
 * @param[out] out Decoded trailer.
 * @return False when the packet declares no trailer.
 */
bool parseTrailer(const uint8_t *vrt, const Header &h, bool swap, Trailer *out);

/**
 * @brief Test whether a datagram plausibly holds a VRT packet.
 *
 * Used by discovery to classify arbitrary traffic. Requires the declared size
 * to account for the datagram, a known packet type, and reserved bits clear
 * for the packet class.
 *
 * @param pkt Datagram bytes.
 * @param len Datagram length in bytes.
 * @param[out] swap Set when the packet decodes only as little-endian.
 * @return True if the datagram is plausibly VRT.
 */
bool looksLikeVRT(const uint8_t *pkt, size_t len, bool *swap);

/**
 * @brief Builds a VRT packet word by word.
 *
 * Words are appended in wire order and the size field is patched by finish().
 * Call begin() first, then the optional prologue setters in the order the
 * spec requires, then the payload.
 */
class Builder {
public:
    /**
     * @brief Construct a builder.
     * @param swap Emit 32-bit words little-endian.
     */
    explicit Builder(bool swap = false) : _swap(swap) {}

    /**
     * @brief Start a packet, discarding any previous contents.
     * @param type Packet type.
     * @param count Modulo-16 packet counter.
     */
    void begin(PacketType type, uint8_t count);

    /**
     * @brief Append the stream identifier.
     * @param sid Stream identifier.
     */
    void setStreamId(uint32_t sid);

    /**
     * @brief Append the class identifier and set its header bit.
     * @param oui Organizationally unique identifier, 24 bits.
     * @param infoClass Information class code.
     * @param packetClass Packet class code.
     */
    void setClassId(uint32_t oui, uint16_t infoClass, uint16_t packetClass);

    /**
     * @brief Append the timestamp and set the header TSI and TSF fields.
     * @param tsi Integer timestamp interpretation.
     * @param seconds Integer timestamp, ignored when @p tsi is TSI_NONE.
     * @param tsf Fractional timestamp interpretation.
     * @param frac Fractional timestamp, ignored when @p tsf is TSF_NONE.
     */
    void setTimestamp(TSI tsi, uint32_t seconds, TSF tsf, uint64_t frac);

    /** @brief Append one 32-bit word. */
    void appendWord(uint32_t w);

    /** @brief Append one 64-bit value as two words, most significant first. */
    void appendU64(uint64_t v);

    /** @brief Append raw bytes, which the caller must keep word aligned. */
    void appendBytes(const uint8_t *p, size_t n);

    /**
     * @brief Append a 64-bit fixed-point value.
     * @param value Value in natural units.
     * @param radix Number of fractional bits.
     */
    void appendFixed64(double value, int radix);

    /**
     * @brief Append two 16-bit fixed-point values packed into one word.
     * @param hi Value for the upper half.
     * @param lo Value for the lower half.
     * @param radix Number of fractional bits.
     */
    void appendFixed16Pair(double hi, double lo, int radix);

    /**
     * @brief Patch the size field and return the finished packet.
     * @return Wire bytes, valid until the builder is reused or destroyed.
     */
    const std::vector<uint8_t> &finish();

    /** @brief Mutable access to the packet under construction. */
    std::vector<uint8_t> &raw() { return _buf; }

private:
    void put32(size_t wordIdx, uint32_t v);
    uint32_t get32(size_t wordIdx) const;

    std::vector<uint8_t> _buf;
    bool     _swap;
    uint32_t _hdr        = 0;
    bool     _haveStream = false;
    bool     _haveClass  = false;
    TSI      _tsi        = TSI_NONE;
    TSF      _tsf        = TSF_NONE;
};

/**
 * @brief Emit a CIF0 indicator word and its field body.
 *
 * Fields flagged in @p info are written in the most-significant-first order
 * the spec requires. Shared by the context packet and command packet builders.
 *
 * @param b Builder positioned where CIF0 belongs.
 * @param info Fields to emit.
 */
void appendCIF0(Builder &b, const ContextInfo &info);

/**
 * @brief Build an IF context packet describing a stream.
 * @param streamId Stream identifier.
 * @param count Modulo-16 packet counter.
 * @param info Fields to emit.
 * @param tsi Integer timestamp interpretation.
 * @param tsInt Integer timestamp.
 * @param tsf Fractional timestamp interpretation.
 * @param tsFrac Fractional timestamp.
 * @param swap Emit 32-bit words little-endian.
 * @return Wire bytes of the finished packet.
 */
std::vector<uint8_t> buildContext(uint32_t streamId, uint8_t count,
                                  const ContextInfo &info,
                                  TSI tsi, uint32_t tsInt,
                                  TSF tsf, uint64_t tsFrac,
                                  bool swap);

/**
 * @brief Read a 32-bit word.
 * @param p Word start.
 * @param swap Read little-endian rather than big-endian.
 * @return Word value.
 */
inline uint32_t rd32(const uint8_t *p, bool swap)
{
    return swap ? ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
                   (uint32_t)p[1] << 8  | (uint32_t)p[0])
                : ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                   (uint32_t)p[2] << 8  | (uint32_t)p[3]);
}

/**
 * @brief Read a 64-bit value from two consecutive words.
 * @param p First word start.
 * @param swap Read each word little-endian rather than big-endian.
 * @return Value with the first word as the most significant half.
 */
inline uint64_t rd64(const uint8_t *p, bool swap)
{
    return ((uint64_t)rd32(p, swap) << 32) | rd32(p + 4, swap);
}

} /* namespace VRT */
