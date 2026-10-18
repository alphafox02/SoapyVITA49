/*
 * Unit tests for the VRT packet layer and sample conversion.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Convert.hpp"
#include "VRT.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond) do {                                                      \
    g_checks++;                                                               \
    if (!(cond)) {                                                            \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
        g_failures++;                                                         \
    }                                                                         \
} while (0)

#define CHECK_NEAR(a, b, tol) do {                                            \
    g_checks++;                                                               \
    double _a = (a), _b = (b);                                                \
    if (fabs(_a - _b) > (tol)) {                                              \
        printf("  FAIL %s:%d: %s (%.6f) != %s (%.6f)\n",                      \
               __FILE__, __LINE__, #a, _a, #b, _b);                           \
        g_failures++;                                                         \
    }                                                                         \
} while (0)

static void put32(std::vector<uint8_t> &v, uint32_t w)
{
    v.push_back((uint8_t)(w >> 24));
    v.push_back((uint8_t)(w >> 16));
    v.push_back((uint8_t)(w >> 8));
    v.push_back((uint8_t)w);
}

static void put64(std::vector<uint8_t> &v, uint64_t x)
{
    put32(v, (uint32_t)(x >> 32));
    put32(v, (uint32_t)x);
}

/* ------------------------------------------------------------------ */

static void testHeaderBasic()
{
    printf("header parsing\n");

    /* Type 1 with stream ID, UTC seconds and picosecond fraction. */
    std::vector<uint8_t> p;
    put32(p, (0x1u << 28) | (1u << 22) | (2u << 20) | (5u << 16) | 10);
    put32(p, 0xDEADBEEF);
    put32(p, 0x12345678u);
    put64(p, 123456789012ULL);
    while (p.size() < 40) p.push_back(0);

    VRT::Header h;
    CHECK(VRT::parseHeader(p.data(), p.size(), false, &h));
    CHECK(h.type == VRT::PKT_SIGNAL_DATA);
    CHECK(h.streamId == 0xDEADBEEF);
    CHECK(h.tsi == VRT::TSI_UTC);
    CHECK(h.tsf == VRT::TSF_REALTIME_PS);
    CHECK(h.count == 5);
    CHECK(h.sizeWords == 10);
    CHECK(h.tsInt == 0x12345678u);
    CHECK(h.tsFrac == 123456789012ULL);
    /* 1 header + 1 stream ID + 1 seconds + 2 fraction = 5 words */
    CHECK(h.payloadOffset == 20);
    CHECK(h.payloadBytes == 20);

    /* Type 0 carries no stream ID. */
    std::vector<uint8_t> q;
    put32(q, (0x0u << 28) | 4);
    while (q.size() < 16) q.push_back(0);
    CHECK(VRT::parseHeader(q.data(), q.size(), false, &h));
    CHECK(!h.hasStreamId);
    CHECK(h.payloadOffset == 4);
    CHECK(h.payloadBytes == 12);

    /* A declared size larger than the buffer must be rejected, not trusted. */
    std::vector<uint8_t> r;
    put32(r, (0x1u << 28) | 100);
    put32(r, 0);
    CHECK(!VRT::parseHeader(r.data(), r.size(), false, &h));
}

static void testTrailerOnlyOnDataPackets()
{
    printf("trailer bit scope\n");

    /* Bit 26 means "trailer present" on a data packet. */
    std::vector<uint8_t> d;
    put32(d, (0x1u << 28) | (1u << 26) | 6);
    put32(d, 1);
    while (d.size() < 24) d.push_back(0);

    VRT::Header h;
    CHECK(VRT::parseHeader(d.data(), d.size(), false, &h));
    CHECK(h.hasTrailer);
    CHECK(h.payloadBytes == 12);   /* 6 words - 1 header - 1 sid - 1 trailer */

    /* On a context packet the same bit means something else entirely, so no
     * trailer word may be subtracted. */
    std::vector<uint8_t> c;
    put32(c, (0x4u << 28) | (1u << 26) | 6);
    put32(c, 1);
    while (c.size() < 24) c.push_back(0);

    CHECK(VRT::parseHeader(c.data(), c.size(), false, &h));
    CHECK(!h.hasTrailer);
    CHECK(h.payloadBytes == 16);   /* 6 words - 1 header - 1 sid */
}

static void testVrlFraming()
{
    printf("VRL framing\n");

    std::vector<uint8_t> p;
    put32(p, VRT::VRL_MAGIC);
    put32(p, 6);                      /* 6 words total in the frame */
    put32(p, (0x1u << 28) | 4);       /* VRT packet, 4 words */
    put32(p, 0x11223344);
    put32(p, 0);
    put32(p, VRT::VRL_END);

    size_t vrtLen = 0;
    size_t off = VRT::vrlStrip(p.data(), p.size(), &vrtLen);
    CHECK(off == 8);
    CHECK(vrtLen == 12);              /* 24 total - 8 header - 4 trailer */

    /* A bare VRT packet must pass through untouched. */
    std::vector<uint8_t> q;
    put32(q, (0x1u << 28) | 2);
    put32(q, 0);
    off = VRT::vrlStrip(q.data(), q.size(), &vrtLen);
    CHECK(off == 0);
    CHECK(vrtLen == 8);
}

static void testContextFields()
{
    printf("context field extraction\n");

    std::vector<uint8_t> p;
    const uint32_t cif0 = VRT::CIF0_RF_REF_FREQ | VRT::CIF0_SAMPLE_RATE;
    put32(p, (0x4u << 28) | 7);       /* header + sid + cif0 + 2 + 2 */
    put32(p, 0x00000001);
    put32(p, cif0);
    put64(p, (uint64_t)((int64_t)2400000000LL << 20));
    put64(p, (uint64_t)((int64_t)30720000LL << 20));

    VRT::ContextInfo ci;
    CHECK(VRT::parseContext(p.data(), p.size(), false, &ci));
    CHECK(ci.haveRfFreq);
    CHECK(ci.haveSampleRate);
    CHECK_NEAR(ci.rfFreq, 2400000000.0, 1.0);
    CHECK_NEAR(ci.sampleRate, 30720000.0, 1.0);
    CHECK(ci.streamId == 1);
}

/*
 * The context field change indicator is an indicator only: it occupies no
 * space in the packet body. Treating it as a one-word field shifts every
 * following field and silently corrupts the frequency and sample rate, which
 * is exactly what happens on a source that flags a change.
 */
static void testChangeIndicatorConsumesNoWords()
{
    printf("change indicator occupies no payload word\n");

    std::vector<uint8_t> p;
    const uint32_t cif0 = VRT::CIF0_CHANGE_IND |
                          VRT::CIF0_RF_REF_FREQ |
                          VRT::CIF0_SAMPLE_RATE;
    put32(p, (0x4u << 28) | 7);
    put32(p, 0x00000002);
    put32(p, cif0);
    put64(p, (uint64_t)((int64_t)1575420000LL << 20));
    put64(p, (uint64_t)((int64_t)2048000LL << 20));

    VRT::ContextInfo ci;
    CHECK(VRT::parseContext(p.data(), p.size(), false, &ci));
    CHECK(ci.changeIndicator);
    CHECK(ci.haveRfFreq);
    CHECK(ci.haveSampleRate);
    CHECK_NEAR(ci.rfFreq, 1575420000.0, 1.0);
    CHECK_NEAR(ci.sampleRate, 2048000.0, 1.0);
}

/* GPS ASCII is variable length; its size lives in its own second word. A fixed
 * guess desynchronises every field after it. */
static void testVariableLengthGpsAscii()
{
    printf("variable length GPS ASCII skip\n");

    std::vector<uint8_t> p;
    const uint32_t cif0 = VRT::CIF0_SAMPLE_RATE |
                          VRT::CIF0_GPS_ASCII |
                          VRT::CIF0_CONTEXT_ASSOC;
    /* header+sid+cif0 = 3, sample rate = 2, gps ascii = 2+3, assoc = 2 */
    put32(p, (0x4u << 28) | (3 + 2 + 5 + 2));
    put32(p, 0x00000003);
    put32(p, cif0);
    put64(p, (uint64_t)((int64_t)1000000LL << 20));
    put32(p, 0x00ABCDEF);             /* GPS ASCII: OUI */
    put32(p, 3);                      /* three words of text follow */
    put32(p, 0x41414141);
    put32(p, 0x42424242);
    put32(p, 0x43434343);
    put32(p, 0);                      /* association list sizes: all empty */
    put32(p, 0);

    VRT::ContextInfo ci;
    CHECK(VRT::parseContext(p.data(), p.size(), false, &ci));
    CHECK(ci.haveSampleRate);
    CHECK_NEAR(ci.sampleRate, 1000000.0, 1.0);
}

static void testPayloadFormat()
{
    printf("payload format decoding\n");

    VRT::ContextInfo ci;

    /* complex cartesian, signed fixed-point, 16-bit items */
    CHECK(VRT::parsePayloadFormat((1u << 29) | (15u << 6) | 15, 0, &ci));
    CHECK(ci.format == VRT::FMT_CI16);

    /* 8-bit */
    CHECK(VRT::parsePayloadFormat((1u << 29) | (7u << 6) | 7, 0, &ci));
    CHECK(ci.format == VRT::FMT_CI8);

    /* link-efficient 12-bit */
    CHECK(VRT::parsePayloadFormat((1u << 31) | (1u << 29) | (11u << 6) | 11, 0, &ci));
    CHECK(ci.format == VRT::FMT_CI12);
    CHECK(ci.linkEfficient);

    /* link-efficient 14-bit (28 bits per complex) */
    CHECK(VRT::parsePayloadFormat((1u << 31) | (1u << 29) | (13u << 6) | 13, 0, &ci));
    CHECK(ci.format == VRT::FMT_CI14);
    CHECK(ci.linkEfficient);

    /* IEEE-754 single precision */
    CHECK(VRT::parsePayloadFormat((1u << 29) | (14u << 24) | (31u << 6) | 31, 0, &ci));
    CHECK(ci.format == VRT::FMT_CF32);

    /* Real-valued data has no complex Soapy equivalent and must be refused. */
    CHECK(!VRT::parsePayloadFormat((0u << 29) | (15u << 6) | 15, 0, &ci));

    /* Data item size is six bits wide, so 32-bit items must decode. A five-bit
     * mask would read 31 as 31 but silently truncate anything above. */
    CHECK(VRT::parsePayloadFormat((1u << 29) | (14u << 24) | (31u << 6) | 31, 0, &ci));
    CHECK(ci.itemSizeBits == 32);
}

static void testClassifier()
{
    printf("stream classifier\n");

    bool swap = false;

    /* A well-formed packet is accepted. */
    std::vector<uint8_t> good;
    put32(good, (0x1u << 28) | 8);
    put32(good, 0x00000001);
    for (int i = 0; i < 6; i++) put32(good, 0x11223344);
    CHECK(VRT::looksLikeVRT(good.data(), good.size(), &swap));
    CHECK(!swap);

    /* The same packet with every header word byte-reversed is recognised as
     * the little-endian dialect. */
    std::vector<uint8_t> swapped(good.size());
    for (size_t i = 0; i < good.size(); i += 4) {
        swapped[i]     = good[i + 3];
        swapped[i + 1] = good[i + 2];
        swapped[i + 2] = good[i + 1];
        swapped[i + 3] = good[i];
    }
    CHECK(VRT::looksLikeVRT(swapped.data(), swapped.size(), &swap));
    CHECK(swap);

    /* Unrelated traffic must not be claimed as VRT. */
    const char *http = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
    CHECK(!VRT::looksLikeVRT((const uint8_t *)http, strlen(http) & ~3u, &swap));

    std::vector<uint8_t> zeros(64, 0);
    CHECK(!VRT::looksLikeVRT(zeros.data(), zeros.size(), &swap));

    /* A payload that is not word aligned cannot be VRT. */
    CHECK(!VRT::looksLikeVRT(good.data(), good.size() - 1, &swap));
}

/*
 * IF context packet whose header sets bit 24, the Timestamp Mode indicator
 * (section 7.1.1.1). Bit 24 is reserved on data packets but not on context
 * packets, so a classifier that rejects it discards every context packet from
 * a source that uses it, losing the sample rate, frequency and payload format
 * while still finding the stream itself.
 *
 * The field values are arbitrary; the packet exists to exercise the header
 * check and the CIF0 field walk.
 */
static const uint8_t kContextWithTsm[64] = {
    /* type 4, TSM set, TSI=UTC, TSF=picoseconds, count 15, 16 words */
    0x41, 0x6f, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x01,    /* stream ID 1 */
    0x00, 0x00, 0x00, 0x00,    /* integer seconds, zero */
    0x00, 0x00, 0x00, 0x74,    /* fractional picoseconds, high */
    0x6a, 0x52, 0x88, 0x00,    /* fractional picoseconds, low */
    /* CIF0: bandwidth, RF ref, ref level, gain, sample rate, format */
    0x29, 0xa0, 0x80, 0x00,
    0x00, 0x00, 0x07, 0xa1,    /* bandwidth 8 MHz */
    0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x5f, 0x5e,    /* RF reference 100 MHz */
    0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xfb, 0x00,    /* reference level -10.00 dBm */
    0x00, 0x00, 0x00, 0x00,    /* gain, both stages zero */
    0x00, 0x00, 0x09, 0x89,    /* sample rate 10 Msps */
    0x68, 0x00, 0x00, 0x00,
    /* complex cartesian, signed fixed-point, 16-bit */
    0x20, 0x00, 0x03, 0xcf,
    0x00, 0x00, 0x00, 0x00,
};

static void testContextTimestampMode()
{
    printf("context packet with the timestamp-mode bit set\n");

    bool swap = true;
    CHECK(VRT::looksLikeVRT(kContextWithTsm, sizeof(kContextWithTsm), &swap));
    CHECK(!swap);

    VRT::Header h;
    CHECK(VRT::parseHeader(kContextWithTsm, sizeof(kContextWithTsm), false, &h));
    CHECK(h.type == VRT::PKT_IF_CONTEXT);
    CHECK(h.streamId == 1);
    CHECK(h.tsi == VRT::TSI_UTC);
    CHECK(h.tsf == VRT::TSF_REALTIME_PS);
    CHECK(h.sizeWords == 16);
    /* A context packet must never be read as carrying a trailer, whatever
     * bit 26 happens to be. */
    CHECK(!h.hasTrailer);

    VRT::ContextInfo ci;
    CHECK(VRT::parseContext(kContextWithTsm, sizeof(kContextWithTsm), false, &ci));
    CHECK(ci.haveSampleRate);
    CHECK_NEAR(ci.sampleRate, 10000000.0, 1.0);
    CHECK(ci.haveRfFreq);
    CHECK_NEAR(ci.rfFreq, 100000000.0, 1.0);
    CHECK(ci.haveBandwidth);
    CHECK_NEAR(ci.bandwidth, 8000000.0, 1.0);
    CHECK(ci.haveRefLevel);
    CHECK_NEAR(ci.refLevel, -10.0, 0.01);
    CHECK(ci.haveFormat);
    CHECK(ci.format == VRT::FMT_CI16);
    CHECK(!ci.linkEfficient);
    CHECK(ci.itemSizeBits == 16);

    /* Bits 25:24 stay reserved on data packets, where a set bit really does
     * mean the datagram is not VRT. */
    std::vector<uint8_t> d;
    put32(d, (0x1u << 28) | (1u << 24) | 8);
    put32(d, 1);
    for (int i = 0; i < 6; i++) put32(d, 0);
    bool sw2 = false;
    CHECK(!VRT::looksLikeVRT(d.data(), d.size(), &sw2));
}

/*
 * Signal data packet carrying a trailer: 2054 words made up of a 5-word
 * prologue, 2048 payload words and one trailer word. Miscounting the trailer
 * hands its four bytes to the application as if they were samples.
 */
static void testDataTrailer()
{
    printf("signal data packet with trailer\n");

    /* Type 1, trailer present (bit 26), TSI=UTC, TSF=picoseconds, count 4,
     * 2054 words. */
    std::vector<uint8_t> p;
    put32(p, 0x14640806u);
    put32(p, 0x00000001);
    put32(p, 0x00000000u);
    put64(p, 500000000000ULL);
    while (p.size() < 2054 * 4) put32(p, 0);
    /* Calibrated time, valid data and reference lock enabled and asserted;
     * over-range enabled and clear; sample loss not reported. */
    p[2053 * 4 + 0] = 0xe2; p[2053 * 4 + 1] = 0x0e;
    p[2053 * 4 + 2] = 0x00; p[2053 * 4 + 3] = 0x00;

    VRT::Header h;
    CHECK(VRT::parseHeader(p.data(), p.size(), false, &h));
    CHECK(h.type == VRT::PKT_SIGNAL_DATA);
    CHECK(h.hasTrailer);
    CHECK(h.sizeWords == 2054);
    CHECK(h.payloadOffset == 20);
    /* 2054 - 5 prologue - 1 trailer = 2048 words = 8192 bytes */
    CHECK(h.payloadBytes == 8192);

    /* 0xe20e0000 decodes as three asserted indicators plus over-range clear. */
    VRT::Trailer tr;
    CHECK(VRT::parseTrailer(p.data(), h, false, &tr));
    CHECK(tr.haveCalibratedTime && tr.calibratedTime);
    CHECK(tr.haveValidData      && tr.validData);
    CHECK(tr.haveReferenceLock  && tr.referenceLock);
    CHECK(tr.haveOverRange      && !tr.overRange);
    /* Sample loss is not enabled by this source, which is different from it
     * being enabled and false. */
    CHECK(!tr.haveSampleLoss);
    CHECK(!tr.sampleLoss);
}

static void testBuilderRoundTrip()
{
    printf("builder round trip\n");

    VRT::ContextInfo out;
    out.haveSampleRate = true; out.sampleRate = 61440000.0;
    out.haveRfFreq     = true; out.rfFreq     = 2412000000.0;
    out.haveBandwidth  = true; out.bandwidth  = 40000000.0;
    out.haveGain       = true; out.gainStage1 = 12.5; out.gainStage2 = -3.25;
    out.haveFormat     = true; out.format     = VRT::FMT_CI16;

    for (int pass = 0; pass < 2; pass++) {
        bool swap = (pass == 1);
        std::vector<uint8_t> pkt = VRT::buildContext(
            0xABCD1234, 3, out, VRT::TSI_UTC, 0x12345678u,
            VRT::TSF_REALTIME_PS, 500000000000ULL, swap);

        VRT::Header h;
        CHECK(VRT::parseHeader(pkt.data(), pkt.size(), swap, &h));
        CHECK(h.type == VRT::PKT_IF_CONTEXT);
        CHECK(h.streamId == 0xABCD1234);
        CHECK(h.count == 3);
        CHECK(h.sizeWords * 4 == pkt.size());

        VRT::ContextInfo back;
        CHECK(VRT::parseContext(pkt.data(), pkt.size(), swap, &back));
        CHECK_NEAR(back.sampleRate, out.sampleRate, 1.0);
        CHECK_NEAR(back.rfFreq,     out.rfFreq,     1.0);
        CHECK_NEAR(back.bandwidth,  out.bandwidth,  1.0);
        CHECK_NEAR(back.gainStage1, out.gainStage1, 0.01);
        CHECK_NEAR(back.gainStage2, out.gainStage2, 0.01);
        CHECK(back.format == VRT::FMT_CI16);
    }
}

static void testAgcModeRoundTrip()
{
    printf("State/Event AGC/MGC round trip\n");

    /* The State/Event word sits between sample rate and data format, so the
     * fields on both sides must still decode. */
    for (int mode = 0; mode < 2; mode++) {
        VRT::ContextInfo out;
        out.haveSampleRate = true; out.sampleRate = 20000000.0;
        out.haveGain       = true; out.gainStage1 = 45.0;
        out.haveAgcMode    = true; out.agcAuto    = mode == 1;
        out.haveFormat     = true; out.format     = VRT::FMT_CI16;
        std::vector<uint8_t> pkt = VRT::buildContext(
            0x00C0FFEE, 1, out, VRT::TSI_NONE, 0, VRT::TSF_NONE, 0, false);
        VRT::ContextInfo back;
        CHECK(VRT::parseContext(pkt.data(), pkt.size(), false, &back));
        CHECK(back.haveAgcMode);
        CHECK(back.agcAuto == (mode == 1));
        CHECK_NEAR(back.sampleRate, 20000000.0, 1.0);
        CHECK_NEAR(back.gainStage1, 45.0, 0.01);
        CHECK(back.format == VRT::FMT_CI16);
    }

    /* An indicator whose enable (bit 28) is clear says nothing. */
    VRT::ContextInfo none;
    none.haveAgcMode = true; none.agcAuto = true;
    std::vector<uint8_t> pkt = VRT::buildContext(
        0x00C0FFEE, 1, none, VRT::TSI_NONE, 0, VRT::TSF_NONE, 0, false);
    size_t last = pkt.size() - 4;            /* the State/Event word */
    pkt[last] &= ~0x10;                      /* clear bit 28, big-endian */
    VRT::ContextInfo back;
    VRT::parseContext(pkt.data(), pkt.size(), false, &back);
    CHECK(!back.haveAgcMode);
}

static void testConversionRoundTrip()
{
    printf("sample conversion round trip\n");

    const size_t n = 256;
    std::vector<float> in(n * 2), out(n * 2);
    for (size_t i = 0; i < n * 2; i++)
        in[i] = (float)sin((double)i * 0.05) * 0.9f;

    const VRT::SampleFormat formats[] = {
        VRT::FMT_CI8, VRT::FMT_CI12, VRT::FMT_CI16, VRT::FMT_CF32
    };
    /* Quantisation error is bounded by one step of the wire format. */
    const double tol[] = { 1.0 / 128, 1.0 / 2048, 1.0 / 32768, 1e-6 };

    for (int f = 0; f < 4; f++) {
        for (int pass = 0; pass < 2; pass++) {
            bool swap = (pass == 1);
            /* 12-bit packing is a bit stream with no byte-swapped variant. */
            if (formats[f] == VRT::FMT_CI12 && swap)
                continue;

            std::vector<uint8_t> wire(Convert::payloadForSamples(n, formats[f]));

            Convert::hostToWire((const uint8_t *)in.data(), Convert::HOST_CF32,
                                wire.data(), formats[f], swap, n);
            CHECK(Convert::samplesInPayload(wire.size(), formats[f]) == n);
            Convert::wireToHost(wire.data(), formats[f], swap,
                                (uint8_t *)out.data(), Convert::HOST_CF32, n);

            double worst = 0.0;
            for (size_t i = 0; i < n * 2; i++)
                worst = std::max(worst, (double)fabs(in[i] - out[i]));
            CHECK_NEAR(worst, 0.0, tol[f] * 1.5);
        }
    }
}

/* Some sources place Q ahead of I. Undoing that is an index toggle within each
 * pair, so it must not disturb the sample count or the values themselves. */
static void testIqSwap()
{
    printf("I and Q exchange\n");

    const size_t n = 4;
    float in[n * 2];
    for (size_t i = 0; i < n * 2; i++)
        in[i] = 0.1f * (float)(i + 1);

    std::vector<uint8_t> wire(Convert::payloadForSamples(n, VRT::FMT_CI16));
    Convert::hostToWire((const uint8_t *)in, Convert::HOST_CF32,
                        wire.data(), VRT::FMT_CI16, false, n, false);

    float plain[n * 2], swapped[n * 2];
    Convert::wireToHost(wire.data(), VRT::FMT_CI16, false,
                        (uint8_t *)plain, Convert::HOST_CF32, n, false);
    Convert::wireToHost(wire.data(), VRT::FMT_CI16, false,
                        (uint8_t *)swapped, Convert::HOST_CF32, n, true);

    for (size_t i = 0; i < n; i++) {
        CHECK_NEAR(swapped[i * 2],     plain[i * 2 + 1], 1e-4);
        CHECK_NEAR(swapped[i * 2 + 1], plain[i * 2],     1e-4);
    }

    /* Swapping on both sides of a round trip must cancel. */
    std::vector<uint8_t> wire2(wire.size());
    Convert::hostToWire((const uint8_t *)in, Convert::HOST_CF32,
                        wire2.data(), VRT::FMT_CI16, false, n, true);
    float back[n * 2];
    Convert::wireToHost(wire2.data(), VRT::FMT_CI16, false,
                        (uint8_t *)back, Convert::HOST_CF32, n, true);
    for (size_t i = 0; i < n * 2; i++)
        CHECK_NEAR(back[i], in[i], 1e-4);
}

static void testCs16PathIsExact()
{
    printf("16-bit integer path is lossless\n");

    /* An int16 wire sample converted to the CS16 host format and back must be
     * bit exact, because the float intermediate has enough mantissa for it. */
    std::vector<uint8_t> wire;
    const int16_t vals[] = { 0, 1, -1, 32767, -32768, 1234, -4321 };
    const size_t n = sizeof(vals) / sizeof(vals[0]) / 2;

    for (size_t i = 0; i < n * 2; i++) {
        wire.push_back((uint8_t)((uint16_t)vals[i] >> 8));
        wire.push_back((uint8_t)((uint16_t)vals[i] & 0xFF));
    }

    std::vector<int16_t> host(n * 2);
    Convert::wireToHost(wire.data(), VRT::FMT_CI16, false,
                        (uint8_t *)host.data(), Convert::HOST_CS16, n);

    /* With a symmetric full scale of 2^15 every value, including both
     * extremes, survives the float intermediate untouched. */
    for (size_t i = 0; i < n * 2; i++)
        CHECK(host[i] == vals[i]);
}

/* Packed 14-bit is receive-only here (the device never transmits it): decode a
 * known 28-byte group and confirm every signed sample, plus that a payload that
 * is not a whole 8-sample group yields no samples. */
static void testPacked14Decode()
{
    printf("packed 14-bit decode\n");

    const int iq[8][2] = {
        {0, 0}, {1, -1}, {8191, -8192}, {-8192, 8191},
        {1234, -4321}, {-1, 1}, {4096, -4096}, {13, -14},
    };
    uint8_t pay[28];
    memset(pay, 0, sizeof(pay));
    for (int k = 0; k < 8; k++) {
        for (int half = 0; half < 2; half++) {
            unsigned v = (unsigned)iq[k][half] & 0x3FFFu;
            size_t base = (size_t)(2 * k + half) * 14;
            for (int b = 13; b >= 0; b--) {
                size_t bp = base + (size_t)(13 - b);
                if ((v >> b) & 1u) pay[bp >> 3] |= (uint8_t)(0x80u >> (bp & 7u));
            }
        }
    }

    CHECK(Convert::samplesInPayload(28, VRT::FMT_CI14) == 8);
    CHECK(Convert::samplesInPayload(27, VRT::FMT_CI14) == 0);   /* no partial group */

    int16_t out[16];
    size_t bytes = Convert::wireToHost(pay, VRT::FMT_CI14, false,
                                       (uint8_t *)out, Convert::HOST_CS16, 8, false);
    CHECK(bytes == 8 * 4);
    for (int k = 0; k < 8; k++) {
        CHECK(out[2 * k]     / 4 == iq[k][0]);   /* CS16 full scale 2^15 vs 2^13 wire */
        CHECK(out[2 * k + 1] / 4 == iq[k][1]);
    }
}

int main()
{
    printf("SoapyVITA49 packet layer tests\n\n");

    testHeaderBasic();
    testTrailerOnlyOnDataPackets();
    testVrlFraming();
    testContextFields();
    testChangeIndicatorConsumesNoWords();
    testVariableLengthGpsAscii();
    testPayloadFormat();
    testClassifier();
    testContextTimestampMode();
    testDataTrailer();
    testBuilderRoundTrip();
    testAgcModeRoundTrip();
    testConversionRoundTrip();
    testIqSwap();
    testCs16PathIsExact();
    testPacked14Decode();

    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
