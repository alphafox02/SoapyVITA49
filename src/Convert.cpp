/*
 * Sample conversion between VRT wire formats and SoapySDR stream formats.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Convert.hpp"

#include <cmath>
#include <cstring>

#include <SoapySDR/Formats.hpp>

namespace Convert {

bool hostFormatFromString(const std::string &s, HostFormat *out)
{
    if (s == SOAPY_SDR_CF32) { *out = HOST_CF32; return true; }
    if (s == SOAPY_SDR_CS16) { *out = HOST_CS16; return true; }
    if (s == SOAPY_SDR_CS8)  { *out = HOST_CS8;  return true; }
    return false;
}

size_t hostBytesPerSample(HostFormat f)
{
    switch (f) {
    case HOST_CF32: return 8;
    case HOST_CS16: return 4;
    case HOST_CS8:  return 2;
    }
    return 0;
}

double hostFullScale(HostFormat f)
{
    switch (f) {
    /* Full scale is 2^(n-1), matching SoapySDR's ConverterPrimitives, so an
     * integer sample survives a conversion round trip unchanged. */
    case HOST_CF32: return 1.0;
    case HOST_CS16: return 32768.0;
    case HOST_CS8:  return 128.0;
    }
    return 1.0;
}

size_t samplesInPayload(size_t nBytes, VRT::SampleFormat wire)
{
    if (wire == VRT::FMT_CI12)
        return nBytes / 3;                 /* 24 bits per complex sample */
    if (wire == VRT::FMT_CI14)
        return (nBytes / 28) * 8;          /* 8 complex per 28 bytes (7 words), no tail padding */
    size_t bps = VRT::bytesPerSample(wire);
    return bps ? nBytes / bps : 0;
}

size_t payloadForSamples(size_t nSamples, VRT::SampleFormat wire)
{
    if (wire == VRT::FMT_CI12)
        return nSamples * 3;
    if (wire == VRT::FMT_CI14)
        return (nSamples / 8) * 28;        /* whole 8-sample groups only */
    return nSamples * VRT::bytesPerSample(wire);
}

/* Headers are 32-bit words, so a byte-swapping source reverses all four bytes
 * of each. Payloads are individual items, and such a source almost always
 * writes its native sample buffer straight out, which reverses the bytes
 * within each I or Q but leaves I ahead of Q. So payloads swap per item, not
 * per word. */

namespace {

/* ---- wire readers: one item to normalised float ---- */

struct RdCI8 {
    static const size_t itemBytes = 1;
    static inline float get(const uint8_t *p, bool)
    {
        return (float)(int8_t)p[0] * (1.0f / 128.0f);
    }
};

struct RdCI16 {
    static const size_t itemBytes = 2;
    static inline float get(const uint8_t *p, bool swap)
    {
        uint16_t v = swap ? (uint16_t)((uint16_t)p[1] << 8 | p[0])
                          : (uint16_t)((uint16_t)p[0] << 8 | p[1]);
        return (float)(int16_t)v * (1.0f / 32768.0f);
    }
};

struct RdCF32 {
    static const size_t itemBytes = 4;
    static inline float get(const uint8_t *p, bool swap)
    {
        uint32_t v = swap ? ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
                             (uint32_t)p[1] << 8  | p[0])
                          : ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                             (uint32_t)p[2] << 8  | p[3]);
        float f;
        memcpy(&f, &v, 4);
        return f;
    }
};

/* ---- wire writers ---- */

struct WrCI8 {
    static const size_t itemBytes = 1;
    static inline void put(uint8_t *p, float v, bool)
    {
        int t = (int)lrintf(v * 128.0f);
        if (t >  127) t =  127;
        if (t < -128) t = -128;
        p[0] = (uint8_t)(int8_t)t;
    }
};

struct WrCI16 {
    static const size_t itemBytes = 2;
    static inline void put(uint8_t *p, float v, bool swap)
    {
        int t = (int)lrintf(v * 32768.0f);
        if (t >  32767) t =  32767;
        if (t < -32768) t = -32768;
        uint16_t u = (uint16_t)(int16_t)t;
        if (swap) { p[0] = (uint8_t)u; p[1] = (uint8_t)(u >> 8); }
        else      { p[0] = (uint8_t)(u >> 8); p[1] = (uint8_t)u; }
    }
};

struct WrCF32 {
    static const size_t itemBytes = 4;
    static inline void put(uint8_t *p, float v, bool swap)
    {
        uint32_t u;
        memcpy(&u, &v, 4);
        if (swap) {
            p[0] = (uint8_t)u;         p[1] = (uint8_t)(u >> 8);
            p[2] = (uint8_t)(u >> 16); p[3] = (uint8_t)(u >> 24);
        } else {
            p[0] = (uint8_t)(u >> 24); p[1] = (uint8_t)(u >> 16);
            p[2] = (uint8_t)(u >> 8);  p[3] = (uint8_t)u;
        }
    }
};

/* ---- host readers and writers (native byte order) ---- */

struct HostCF32 {
    static const size_t itemBytes = 4;
    static inline float get(const uint8_t *p) { float f; memcpy(&f, p, 4); return f; }
    static inline void  put(uint8_t *p, float v) { memcpy(p, &v, 4); }
};

struct HostCS16 {
    static const size_t itemBytes = 2;
    static inline float get(const uint8_t *p)
    {
        int16_t v; memcpy(&v, p, 2);
        return (float)v * (1.0f / 32768.0f);
    }
    static inline void put(uint8_t *p, float v)
    {
        int t = (int)lrintf(v * 32768.0f);
        if (t >  32767) t =  32767;
        if (t < -32768) t = -32768;
        int16_t s = (int16_t)t;
        memcpy(p, &s, 2);
    }
};

struct HostCS8 {
    static const size_t itemBytes = 1;
    static inline float get(const uint8_t *p)
    {
        return (float)(int8_t)p[0] * (1.0f / 128.0f);
    }
    static inline void put(uint8_t *p, float v)
    {
        int t = (int)lrintf(v * 128.0f);
        if (t >  127) t =  127;
        if (t < -128) t = -128;
        p[0] = (uint8_t)(int8_t)t;
    }
};

template <class Wire, class Host>
inline void rxLoop(const uint8_t *src, bool swap, uint8_t *dst, size_t nItems,
                   bool swapIq)
{
    for (size_t i = 0; i < nItems; i++) {
        size_t o = swapIq ? (i ^ 1) : i;
        Host::put(dst + o * Host::itemBytes,
                  Wire::get(src + i * Wire::itemBytes, swap));
    }
}

template <class Host, class Wire>
inline void txLoop(const uint8_t *src, uint8_t *dst, bool swap, size_t nItems,
                   bool swapIq)
{
    for (size_t i = 0; i < nItems; i++) {
        size_t o = swapIq ? (i ^ 1) : i;
        Wire::put(dst + o * Wire::itemBytes,
                  Host::get(src + i * Host::itemBytes), swap);
    }
}

/* 12-bit link-efficient packing is a bit stream: items sit back to back, MSB
 * first, so item k starts at bit k*12. It is defined over the big-endian word
 * stream, so there is no little-endian variant. */
inline int16_t read12(const uint8_t *src, size_t k)
{
    size_t bit  = k * 12;
    size_t byte = bit >> 3;
    unsigned off = (unsigned)(bit & 7);
    uint32_t w = ((uint32_t)src[byte] << 16) |
                 ((uint32_t)src[byte + 1] << 8) |
                  (uint32_t)src[byte + 2];
    uint32_t v = (w >> (12 - off)) & 0xFFF;
    if (v & 0x800)
        v |= 0xFFFFF000u;                  /* sign extend */
    return (int16_t)(int32_t)v;
}

inline void write12(uint8_t *dst, size_t k, int16_t val)
{
    size_t bit  = k * 12;
    size_t byte = bit >> 3;
    unsigned off = (unsigned)(bit & 7);
    uint32_t v = (uint32_t)val & 0xFFF;
    uint32_t w = ((uint32_t)dst[byte] << 16) |
                 ((uint32_t)dst[byte + 1] << 8) |
                  (uint32_t)dst[byte + 2];
    uint32_t mask = 0xFFFu << (12 - off);
    w = (w & ~mask) | (v << (12 - off));
    dst[byte]     = (uint8_t)(w >> 16);
    dst[byte + 1] = (uint8_t)(w >> 8);
    dst[byte + 2] = (uint8_t)w;
}

template <class Host>
inline void rxLoop12(const uint8_t *src, uint8_t *dst, size_t nItems, bool swapIq)
{
    for (size_t i = 0; i < nItems; i++) {
        size_t o = swapIq ? (i ^ 1) : i;
        Host::put(dst + o * Host::itemBytes, (float)read12(src, i) * (1.0f / 2048.0f));
    }
}

template <class Host>
inline void txLoop12(const uint8_t *src, uint8_t *dst, size_t nItems, bool swapIq)
{
    for (size_t i = 0; i < nItems; i++) {
        size_t o = swapIq ? (i ^ 1) : i;
        float v = Host::get(src + o * Host::itemBytes);
        int t = (int)lrintf(v * 2048.0f);
        if (t >  2047) t =  2047;
        if (t < -2048) t = -2048;
        write12(dst, i, (int16_t)t);
    }
}

/* 14-bit link-efficient packing: items back to back, MSB first, item k at bit
 * k*14 of the big-endian byte stream. Reads only the two or three bytes the
 * field spans, so a payload sized to its item count is not over-read. */
inline int16_t read14(const uint8_t *src, size_t k)
{
    size_t bit  = k * 14;
    size_t byte = bit >> 3;
    unsigned off = (unsigned)(bit & 7);
    uint32_t w = ((uint32_t)src[byte] << 8) | src[byte + 1];
    unsigned total = 16;
    if (off + 14 > 16) { w = (w << 8) | src[byte + 2]; total = 24; }
    uint32_t v = (w >> (total - off - 14)) & 0x3FFFu;
    if (v & 0x2000u)
        v |= 0xFFFFC000u;                  /* sign extend */
    return (int16_t)(int32_t)v;
}

template <class Host>
inline void rxLoop14(const uint8_t *src, uint8_t *dst, size_t nItems, bool swapIq)
{
    for (size_t i = 0; i < nItems; i++) {
        size_t o = swapIq ? (i ^ 1) : i;
        Host::put(dst + o * Host::itemBytes, (float)read14(src, i) * (1.0f / 8192.0f));
    }
}

} /* anonymous namespace */

size_t wireToHost(const uint8_t *src, VRT::SampleFormat wire, bool swap,
                  uint8_t *dst, HostFormat host, size_t nSamples, bool swapIq)
{
    size_t nItems = nSamples * 2;

    switch (wire) {
    case VRT::FMT_CI8:
        switch (host) {
        case HOST_CF32: rxLoop<RdCI8, HostCF32>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS16: rxLoop<RdCI8, HostCS16>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS8:  memcpy(dst, src, nItems); break;   /* identical layout */
        }
        break;
    case VRT::FMT_CI16:
        switch (host) {
        case HOST_CF32: rxLoop<RdCI16, HostCF32>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS16: rxLoop<RdCI16, HostCS16>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS8:  rxLoop<RdCI16, HostCS8>(src, swap, dst, nItems, swapIq);  break;
        }
        break;
    case VRT::FMT_CF32:
        switch (host) {
        case HOST_CF32: rxLoop<RdCF32, HostCF32>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS16: rxLoop<RdCF32, HostCS16>(src, swap, dst, nItems, swapIq); break;
        case HOST_CS8:  rxLoop<RdCF32, HostCS8>(src, swap, dst, nItems, swapIq);  break;
        }
        break;
    case VRT::FMT_CI12:
        switch (host) {
        case HOST_CF32: rxLoop12<HostCF32>(src, dst, nItems, swapIq); break;
        case HOST_CS16: rxLoop12<HostCS16>(src, dst, nItems, swapIq); break;
        case HOST_CS8:  rxLoop12<HostCS8>(src, dst, nItems, swapIq);  break;
        }
        break;
    case VRT::FMT_CI14:
        switch (host) {
        case HOST_CF32: rxLoop14<HostCF32>(src, dst, nItems, swapIq); break;
        case HOST_CS16: rxLoop14<HostCS16>(src, dst, nItems, swapIq); break;
        case HOST_CS8:  rxLoop14<HostCS8>(src, dst, nItems, swapIq);  break;
        }
        break;
    default:
        return 0;
    }

    return nSamples * hostBytesPerSample(host);
}

size_t hostToWire(const uint8_t *src, HostFormat host,
                  uint8_t *dst, VRT::SampleFormat wire, bool swap,
                  size_t nSamples, bool swapIq)
{
    size_t nItems = nSamples * 2;

    switch (wire) {
    case VRT::FMT_CI8:
        switch (host) {
        case HOST_CF32: txLoop<HostCF32, WrCI8>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS16: txLoop<HostCS16, WrCI8>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS8:
            if (swapIq) rxLoop<RdCI8, HostCS8>(src, swap, dst, nItems, true);
            else        memcpy(dst, src, nItems);
            break;
        }
        break;
    case VRT::FMT_CI16:
        switch (host) {
        case HOST_CF32: txLoop<HostCF32, WrCI16>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS16: txLoop<HostCS16, WrCI16>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS8:  txLoop<HostCS8,  WrCI16>(src, dst, swap, nItems, swapIq); break;
        }
        break;
    case VRT::FMT_CF32:
        switch (host) {
        case HOST_CF32: txLoop<HostCF32, WrCF32>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS16: txLoop<HostCS16, WrCF32>(src, dst, swap, nItems, swapIq); break;
        case HOST_CS8:  txLoop<HostCS8,  WrCF32>(src, dst, swap, nItems, swapIq); break;
        }
        break;
    case VRT::FMT_CI12:
        memset(dst, 0, payloadForSamples(nSamples, wire));
        switch (host) {
        case HOST_CF32: txLoop12<HostCF32>(src, dst, nItems, swapIq); break;
        case HOST_CS16: txLoop12<HostCS16>(src, dst, nItems, swapIq); break;
        case HOST_CS8:  txLoop12<HostCS8>(src, dst, nItems, swapIq);  break;
        }
        break;
    default:
        return 0;
    }

    return payloadForSamples(nSamples, wire);
}

} /* namespace Convert */
