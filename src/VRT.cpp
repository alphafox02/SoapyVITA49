/*
 * VRT packet layer for VITA 49.0 and VITA 49.2.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "VRT.hpp"

#include <cstring>

namespace VRT {

const char *formatName(SampleFormat f)
{
    switch (f) {
    case FMT_CI8:  return "ci8";
    case FMT_CI12: return "ci12";
    case FMT_CI16: return "ci16";
    case FMT_CF32: return "cf32";
    default:       return "unknown";
    }
}

size_t bytesPerSample(SampleFormat f)
{
    switch (f) {
    case FMT_CI8:  return 2;
    case FMT_CI12: return 3;
    case FMT_CI16: return 4;
    case FMT_CF32: return 8;
    default:       return 0;
    }
}

size_t vrlStrip(const uint8_t *pkt, size_t len, size_t *vrtLen)
{
    /* VRL frame: "VRLP" + 32-bit frame count/size word + VRT packet(s) +
     * 4-byte trailer that is either "VEND" or a CRC32. The frame size word
     * counts the entire frame in 32-bit words including header and trailer. */
    if (len >= 12 && rd32(pkt, false) == VRL_MAGIC) {
        size_t frameWords = rd32(pkt + 4, false) & 0x000FFFFF;
        size_t frameBytes = frameWords * 4;
        if (frameBytes >= 12 && frameBytes <= len)
            *vrtLen = frameBytes - 12;
        else
            *vrtLen = len - 12;   /* size word disagrees; trust the datagram */
        return 8;
    }
    *vrtLen = len;
    return 0;
}

bool parseHeader(const uint8_t *vrt, size_t len, bool swap, Header *out)
{
    if (len < 4)
        return false;

    uint32_t w0 = rd32(vrt, swap);

    out->type       = (PacketType)((w0 >> 28) & 0xF);
    out->hasClassId = (w0 >> 27) & 1;
    out->count      = (w0 >> 16) & 0xF;
    out->sizeWords  = w0 & 0xFFFF;
    out->tsi        = (TSI)((w0 >> 22) & 0x3);
    out->tsf        = (TSF)((w0 >> 20) & 0x3);

    /* Bit 26 is the trailer indicator on data packets only. On context and
     * command packets that bit carries other meaning (49.2 uses it for the
     * "not a V49.0 packet" and acknowledge flags respectively), so a trailer
     * must never be assumed outside the data classes. */
    bool isData = (out->type == PKT_SIGNAL_DATA_NO_SID ||
                   out->type == PKT_SIGNAL_DATA ||
                   out->type == PKT_EXT_DATA_NO_SID ||
                   out->type == PKT_EXT_DATA);
    out->hasTrailer = isData && ((w0 >> 26) & 1);

    /* Stream ID is optional only on data packet types 0 and 2; every context
     * and command packet carries one. */
    out->hasStreamId = (out->type != PKT_SIGNAL_DATA_NO_SID &&
                        out->type != PKT_EXT_DATA_NO_SID);

    size_t pktBytes = out->sizeWords * 4;
    if (out->sizeWords < 1 || pktBytes > len)
        return false;

    size_t w = 1;
    out->streamId = 0;
    if (out->hasStreamId) {
        if ((w + 1) * 4 > pktBytes) return false;
        out->streamId = rd32(vrt + w * 4, swap);
        w += 1;
    }

    out->classId = 0;
    if (out->hasClassId) {
        if ((w + 2) * 4 > pktBytes) return false;
        out->classId = rd64(vrt + w * 4, swap);
        w += 2;
    }

    out->tsInt = 0;
    if (out->tsi != TSI_NONE) {
        if ((w + 1) * 4 > pktBytes) return false;
        out->tsInt = rd32(vrt + w * 4, swap);
        w += 1;
    }

    out->tsFrac = 0;
    if (out->tsf != TSF_NONE) {
        if ((w + 2) * 4 > pktBytes) return false;
        out->tsFrac = rd64(vrt + w * 4, swap);
        w += 2;
    }

    size_t trailerWords = out->hasTrailer ? 1 : 0;
    if (w + trailerWords > out->sizeWords)
        return false;

    out->payloadOffset = w * 4;
    out->payloadBytes  = (out->sizeWords - w - trailerWords) * 4;
    return true;
}

/* CIF0 field sizes in 32-bit words, MSB-first. Bit 31 is the Context Field
 * Change Indicator, which occupies no space in the body (section 7.1.5.1);
 * giving it a word shifts every field after it. Bits 9 and 8 are variable
 * length and handled in the walk. */
struct CIF0Field { uint32_t bit; int words; };

static const CIF0Field kCIF0[] = {
    { CIF0_CHANGE_IND,        0 },
    { CIF0_REF_POINT_ID,      1 },
    { CIF0_BANDWIDTH,         2 },
    { CIF0_IF_REF_FREQ,       2 },
    { CIF0_RF_REF_FREQ,       2 },
    { CIF0_RF_FREQ_OFFSET,    2 },
    { CIF0_IF_BAND_OFFSET,    2 },
    { CIF0_REF_LEVEL,         1 },
    { CIF0_GAIN,              1 },
    { CIF0_OVER_RANGE_COUNT,  1 },
    { CIF0_SAMPLE_RATE,       2 },
    { CIF0_TS_ADJUSTMENT,     2 },
    { CIF0_TS_CALIB_TIME,     1 },
    { CIF0_TEMPERATURE,       1 },
    { CIF0_DEVICE_ID,         2 },
    { CIF0_STATE_EVENT,       1 },
    { CIF0_DATA_FORMAT,       2 },
    { CIF0_FORMATTED_GPS,    11 },
    { CIF0_FORMATTED_INS,    11 },
    { CIF0_ECEF_EPHEMERIS,   13 },
    { CIF0_REL_EPHEMERIS,    13 },
    { CIF0_EPHEMERIS_REF_ID,  1 },
    { CIF0_GPS_ASCII,        -1 },   /* 2 + word count from second word */
    { CIF0_CONTEXT_ASSOC,    -1 },   /* 2 + list sizes from first two words */
};

/* Two's-complement 64-bit fixed point to double. */
static double fixed64(uint64_t raw, int radix)
{
    return (double)(int64_t)raw / (double)(1LL << radix);
}

static double fixed16(uint16_t raw, int radix)
{
    return (double)(int16_t)raw / (double)(1 << radix);
}

bool parsePayloadFormat(uint32_t w1, uint32_t w2, ContextInfo *out)
{
    (void)w2;   /* word 2 carries vector/repeat counts we do not use */

    unsigned packing   = (w1 >> 31) & 0x1;    /* 0 processing-efficient, 1 link */
    unsigned realCplx  = (w1 >> 29) & 0x3;    /* 1 = complex cartesian */
    unsigned itemFmt   = (w1 >> 24) & 0x1F;
    unsigned fieldBits = ((w1 >> 6) & 0x3F) + 1;   /* item packing field size */
    unsigned itemBits  = (w1 & 0x3F) + 1;          /* data item size */

    out->linkEfficient = (packing == 1);
    out->itemSizeBits  = itemBits;
    out->packingBits   = fieldBits;

    /* Only complex cartesian is usable as SDR IQ. Real and complex-polar
     * streams are valid VRT but have no Soapy equivalent. */
    if (realCplx != 1)
        return false;

    switch (itemFmt) {
    case 0:   /* signed fixed-point */
    case 7:   /* signed fixed-point, non-normalized */
        if (itemBits == 8  && fieldBits == 8)  { out->format = FMT_CI8;  return true; }
        if (itemBits == 16 && fieldBits == 16) { out->format = FMT_CI16; return true; }
        /* 12-bit only decodes when packed link-efficiently into 12-bit fields;
         * a 12-in-16 processing-efficient stream is read as ci16 by the
         * receiver with the low nibble as noise, which is harmless. */
        if (itemBits == 12 && fieldBits == 12) { out->format = FMT_CI12; return true; }
        if (itemBits == 12 && fieldBits == 16) { out->format = FMT_CI16; return true; }
        return false;
    case 14:  /* IEEE-754 single precision */
        if (itemBits == 32) { out->format = FMT_CF32; return true; }
        return false;
    default:
        return false;
    }
}

bool parseTrailer(const uint8_t *vrt, const Header &h, bool swap, Trailer *out)
{
    if (!h.hasTrailer || h.sizeWords < 2)
        return false;

    uint32_t t = rd32(vrt + (h.sizeWords - 1) * 4, swap);

    /* Enable at bit N+12 governs the indicator at bit N, so a pair is only
     * meaningful when the enable is set. */
    struct { unsigned bit; bool *have; bool *value; } fields[] = {
        { 19, &out->haveCalibratedTime, &out->calibratedTime },
        { 18, &out->haveValidData,      &out->validData      },
        { 17, &out->haveReferenceLock,  &out->referenceLock  },
        { 16, &out->haveAgc,            &out->agc            },
        { 15, &out->haveDetectedSignal, &out->detectedSignal },
        { 14, &out->haveSpectralInv,    &out->spectralInv    },
        { 13, &out->haveOverRange,      &out->overRange      },
        { 12, &out->haveSampleLoss,     &out->sampleLoss     },
    };

    for (const auto &f : fields) {
        bool enabled = ((t >> (f.bit + 12)) & 1) != 0;
        *f.have  = enabled;
        *f.value = enabled && (((t >> f.bit) & 1) != 0);
    }

    out->haveContextCount = ((t >> 7) & 1) != 0;
    out->contextCount     = t & 0x7F;
    return true;
}

bool parseContext(const uint8_t *vrt, size_t len, bool swap, ContextInfo *out)
{
    Header h;
    if (!parseHeader(vrt, len, swap, &h))
        return false;
    if (h.type != PKT_IF_CONTEXT && h.type != PKT_EXT_CONTEXT)
        return false;

    out->streamId = h.streamId;
    return parseCIF0(vrt, h.sizeWords, h.payloadOffset / 4, swap, out);
}

bool parseCIF0(const uint8_t *vrt, size_t sizeWords, size_t startWord,
               bool swap, ContextInfo *out)
{
    size_t w = startWord;
    if (w >= sizeWords)
        return false;

    uint32_t cif0 = rd32(vrt + w * 4, swap);
    w += 1;

    /* CIF1/2/3 enable bits each insert another indicator word ahead of the
     * field body. We do not decode those planes but must skip their words to
     * keep the CIF0 field offsets correct. */
    unsigned extraCif = 0;
    if (cif0 & CIF0_CIF1_ENABLE) extraCif++;
    if (cif0 & CIF0_CIF2_ENABLE) extraCif++;
    if (cif0 & CIF0_CIF3_ENABLE) extraCif++;
    if (cif0 & CIF0_CIF7_ENABLE) extraCif++;
    w += extraCif;

    out->changeIndicator = (cif0 & CIF0_CHANGE_IND) != 0;

    bool any = false;

    for (size_t i = 0; i < sizeof(kCIF0) / sizeof(kCIF0[0]); i++) {
        uint32_t bit = kCIF0[i].bit;
        if (!(cif0 & bit))
            continue;

        int words = kCIF0[i].words;

        if (words < 0) {
            /* Variable-length fields. Their sizes live in their own leading
             * words, so a wrong guess desynchronises everything after them. */
            if (bit == CIF0_GPS_ASCII) {
                if (w + 2 > sizeWords) return false;
                uint32_t n = rd32(vrt + (w + 1) * 4, swap) & 0x00FFFFFF;
                words = 2 + (int)n;
            } else {   /* CIF0_CONTEXT_ASSOC */
                if (w + 2 > sizeWords) return false;
                uint32_t a = rd32(vrt + w * 4, swap);
                uint32_t b = rd32(vrt + (w + 1) * 4, swap);
                unsigned srcSz   = (a >> 16) & 0x01FF;
                unsigned sysSz   =  a        & 0x01FF;
                unsigned vecSz   = (b >> 16) & 0xFFFF;
                unsigned asyncSz =  b        & 0x7FFF;
                bool asyncTags   = (b >> 31) & 1;
                words = 2 + (int)(srcSz + sysSz + vecSz + asyncSz);
                if (asyncTags) words += (int)asyncSz;
            }
        }

        if (words == 0)
            continue;   /* indicator-only bit */

        if (w + (size_t)words > sizeWords)
            return false;

        const uint8_t *f = vrt + w * 4;

        switch (bit) {
        case CIF0_BANDWIDTH:
            out->bandwidth = fixed64(rd64(f, swap), RADIX_BANDWIDTH);
            out->haveBandwidth = true; any = true;
            break;
        case CIF0_IF_REF_FREQ:
            out->ifFreq = fixed64(rd64(f, swap), RADIX_FREQ_HZ);
            out->haveIfFreq = true; any = true;
            break;
        case CIF0_RF_REF_FREQ:
            out->rfFreq = fixed64(rd64(f, swap), RADIX_FREQ_HZ);
            out->haveRfFreq = true; any = true;
            break;
        case CIF0_REF_LEVEL:
            /* 16-bit value in the low half of the word (section 7.1.5.8) */
            out->refLevel = fixed16((uint16_t)(rd32(f, swap) & 0xFFFF), RADIX_REF_LEVEL);
            out->haveRefLevel = true; any = true;
            break;
        case CIF0_GAIN: {
            /* Stage 2 in the upper half, stage 1 in the lower (7.1.5.9). A
             * source using a single gain stage puts it in stage 1. */
            uint32_t g = rd32(f, swap);
            out->gainStage2 = fixed16((uint16_t)(g >> 16), RADIX_GAIN_DB);
            out->gainStage1 = fixed16((uint16_t)(g & 0xFFFF), RADIX_GAIN_DB);
            out->haveGain = true; any = true;
            break;
        }
        case CIF0_OVER_RANGE_COUNT:
            out->overRange = rd32(f, swap);
            out->haveOverRange = true; any = true;
            break;
        case CIF0_SAMPLE_RATE:
            out->sampleRate = fixed64(rd64(f, swap), RADIX_SAMP_RATE);
            out->haveSampleRate = true; any = true;
            break;
        case CIF0_TEMPERATURE:
            out->temperature = fixed16((uint16_t)(rd32(f, swap) & 0xFFFF), RADIX_TEMP_C);
            out->haveTemperature = true; any = true;
            break;
        case CIF0_DEVICE_ID:
            /* Word 1 carries the OUI in its low 24 bits, word 2 the device
             * code in its low 16 (section 7.1.5.19). This is one of the two
             * places a source may identify itself. */
            out->deviceOui  = rd32(f, swap) & 0x00FFFFFF;
            out->deviceCode = (uint16_t)(rd32(f + 4, swap) & 0xFFFF);
            out->haveDeviceId = true;
            any = true;
            break;
        case CIF0_DATA_FORMAT:
            if (parsePayloadFormat(rd32(f, swap), rd32(f + 4, swap), out)) {
                out->haveFormat = true; any = true;
            }
            break;
        default:
            break;
        }

        w += (size_t)words;
    }

    return any || out->changeIndicator;
}

bool looksLikeVRT(const uint8_t *pkt, size_t len, bool *swap)
{
    if (len < 8 || (len & 3))
        return false;   /* VRT is word aligned; UDP payload must be too */

    for (int pass = 0; pass < 2; pass++) {
        bool sw = (pass == 1);

        size_t vrtLen = 0;
        size_t off = vrlStrip(pkt, len, &vrtLen);
        if (vrtLen < 8)
            continue;

        Header h;
        if (!parseHeader(pkt + off, vrtLen, sw, &h))
            continue;

        /* The declared size must account for essentially the whole datagram.
         * Random UDP traffic almost never satisfies this. Allow slack for a
         * VRL trailer or a source that pads to a fixed MTU. */
        size_t declared = h.sizeWords * 4;
        if (declared < 16 || declared + 8 < vrtLen)
            continue;

        /*
         * Reserved-bit checks, which differ by packet class. Getting this
         * wrong rejects perfectly valid streams, so only bits that really are
         * reserved for that class are tested.
         *
         * Data packets (types 0-3): bits 25:24 are reserved.
         * Context packets (4-5): bit 24 is the Timestamp Mode indicator
         *   (section 7.1.1.1) and is routinely set by real sources, so only
         *   bit 25 is reserved.
         * Command packets (6-7): 49.2 assigns bit 26 to acknowledge and bit 24
         *   to cancel, leaving nothing here worth testing.
         */
        uint32_t w0 = rd32(pkt + off, sw);
        if (h.type <= PKT_EXT_DATA) {
            if (((w0 >> 24) & 0x3) != 0)
                continue;
        } else if (h.type <= PKT_EXT_CONTEXT) {
            if (((w0 >> 25) & 0x1) != 0)
                continue;
        }

        if (h.type > PKT_EXT_COMMAND)
            continue;

        if (swap) *swap = sw;
        return true;
    }

    return false;
}

/* ------------------------------------------------------------------ */
/* Builder                                                            */
/* ------------------------------------------------------------------ */

void Builder::put32(size_t wordIdx, uint32_t v)
{
    uint8_t *p = _buf.data() + wordIdx * 4;
    if (_swap) {
        p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    } else {
        p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
    }
}

uint32_t Builder::get32(size_t wordIdx) const
{
    return rd32(_buf.data() + wordIdx * 4, _swap);
}

void Builder::begin(PacketType type, uint8_t count)
{
    _buf.clear();
    _haveStream = false;
    _haveClass  = false;
    _tsi = TSI_NONE;
    _tsf = TSF_NONE;
    _hdr = ((uint32_t)type << 28) | ((uint32_t)(count & 0xF) << 16);
    appendWord(_hdr);
}

void Builder::setStreamId(uint32_t sid)
{
    appendWord(sid);
    _haveStream = true;
}

void Builder::setClassId(uint32_t oui, uint16_t infoClass, uint16_t packetClass)
{
    /* Word 1 of the class ID holds a 24-bit OUI in its low bits; the upper
     * byte is reserved and transmitted as zero (section 7.1.3). */
    appendWord(oui & 0x00FFFFFF);
    appendWord(((uint32_t)infoClass << 16) | packetClass);
    _hdr |= (1u << 27);
    put32(0, _hdr);
    _haveClass = true;
}

void Builder::setTimestamp(TSI tsi, uint32_t seconds, TSF tsf, uint64_t frac)
{
    _tsi = tsi;
    _tsf = tsf;
    _hdr |= ((uint32_t)tsi << 22) | ((uint32_t)tsf << 20);
    put32(0, _hdr);
    if (tsi != TSI_NONE)
        appendWord(seconds);
    if (tsf != TSF_NONE)
        appendU64(frac);
}

void Builder::appendWord(uint32_t w)
{
    size_t idx = _buf.size() / 4;
    _buf.resize(_buf.size() + 4);
    put32(idx, w);
}

void Builder::appendU64(uint64_t v)
{
    appendWord((uint32_t)(v >> 32));
    appendWord((uint32_t)(v & 0xFFFFFFFFu));
}

void Builder::appendBytes(const uint8_t *p, size_t n)
{
    _buf.insert(_buf.end(), p, p + n);
}

void Builder::appendFixed64(double value, int radix)
{
    appendU64((uint64_t)(int64_t)(value * (double)(1LL << radix)));
}

void Builder::appendFixed16Pair(double hi, double lo, int radix)
{
    uint16_t h = (uint16_t)(int16_t)(hi * (double)(1 << radix));
    uint16_t l = (uint16_t)(int16_t)(lo * (double)(1 << radix));
    appendWord(((uint32_t)h << 16) | l);
}

const std::vector<uint8_t> &Builder::finish()
{
    /* Pad to a word boundary in case a raw payload was appended unaligned,
     * then write the total size into header bits 15:0. */
    while (_buf.size() & 3)
        _buf.push_back(0);

    uint32_t w0 = get32(0);
    w0 = (w0 & 0xFFFF0000u) | (uint32_t)(_buf.size() / 4);
    put32(0, w0);
    return _buf;
}

void appendCIF0(Builder &b, const ContextInfo &info)
{
    uint32_t cif0 = 0;
    if (info.changeIndicator) cif0 |= CIF0_CHANGE_IND;
    if (info.haveBandwidth)   cif0 |= CIF0_BANDWIDTH;
    if (info.haveIfFreq)      cif0 |= CIF0_IF_REF_FREQ;
    if (info.haveRfFreq)      cif0 |= CIF0_RF_REF_FREQ;
    if (info.haveRefLevel)    cif0 |= CIF0_REF_LEVEL;
    if (info.haveGain)        cif0 |= CIF0_GAIN;
    if (info.haveOverRange)   cif0 |= CIF0_OVER_RANGE_COUNT;
    if (info.haveSampleRate)  cif0 |= CIF0_SAMPLE_RATE;
    if (info.haveFormat)      cif0 |= CIF0_DATA_FORMAT;
    b.appendWord(cif0);

    /* Fields must follow in CIF0 MSB-first order. */
    if (info.haveBandwidth)  b.appendFixed64(info.bandwidth, RADIX_BANDWIDTH);
    if (info.haveIfFreq)     b.appendFixed64(info.ifFreq,    RADIX_FREQ_HZ);
    if (info.haveRfFreq)     b.appendFixed64(info.rfFreq,    RADIX_FREQ_HZ);
    if (info.haveRefLevel)   b.appendFixed16Pair(0.0, info.refLevel, RADIX_REF_LEVEL);
    if (info.haveGain)
        b.appendFixed16Pair(info.gainStage2, info.gainStage1, RADIX_GAIN_DB);
    if (info.haveOverRange)  b.appendWord(info.overRange);
    if (info.haveSampleRate) b.appendFixed64(info.sampleRate, RADIX_SAMP_RATE);

    if (info.haveFormat) {
        unsigned itemFmt  = 0;    /* signed fixed-point */
        unsigned itemBits = 16;
        switch (info.format) {
        case FMT_CI8:  itemBits = 8;  break;
        case FMT_CI12: itemBits = 12; break;
        case FMT_CI16: itemBits = 16; break;
        case FMT_CF32: itemFmt = 14; itemBits = 32; break;
        default: break;
        }
        unsigned fieldBits =
            (info.format == FMT_CI12 && info.linkEfficient) ? 12 : itemBits;

        uint32_t w1 = 0;
        if (info.linkEfficient) w1 |= (1u << 31);
        w1 |= (1u << 29);                       /* complex cartesian */
        w1 |= ((uint32_t)itemFmt & 0x1F) << 24;
        w1 |= ((uint32_t)(fieldBits - 1) & 0x3F) << 6;
        w1 |= ((uint32_t)(itemBits - 1) & 0x3F);
        b.appendWord(w1);
        b.appendWord(0);   /* no vector or repeat structure */
    }
}

std::vector<uint8_t> buildContext(uint32_t streamId, uint8_t count,
                                  const ContextInfo &info,
                                  TSI tsi, uint32_t tsInt,
                                  TSF tsf, uint64_t tsFrac,
                                  bool swap)
{
    Builder b(swap);
    b.begin(PKT_IF_CONTEXT, count);
    b.setStreamId(streamId);
    b.setTimestamp(tsi, tsInt, tsf, tsFrac);
    appendCIF0(b, info);
    return b.finish();
}

} /* namespace VRT */
