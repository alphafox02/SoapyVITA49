/*
 * Sample conversion between VRT wire formats and SoapySDR stream formats.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "VRT.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * @file Convert.hpp
 * @brief Conversion between wire and host sample formats.
 *
 * Full scale is 2^(n-1) in both directions, matching SoapySDR's converter
 * primitives, so an integer sample survives a round trip unchanged.
 *
 * The swap flag applies per item rather than per 32-bit word. A source that
 * emits little-endian generally writes its native sample buffer straight out,
 * which reverses the bytes within each I or Q value but leaves I ahead of Q.
 */

namespace Convert {

/** @brief SoapySDR stream formats this module produces and consumes. */
enum HostFormat {
    HOST_CF32 = 0, /**< Complex float32, native byte order. */
    HOST_CS16,     /**< Complex int16, native byte order. */
    HOST_CS8,      /**< Complex int8. */
};

/**
 * @brief Map a SoapySDR format string to a HostFormat.
 * @param s Format string such as SOAPY_SDR_CF32.
 * @param[out] out Matching enumerator.
 * @return False if the format is not supported.
 */
bool hostFormatFromString(const std::string &s, HostFormat *out);

/**
 * @brief Host size of one complex sample.
 * @param f Host format.
 * @return Bytes per complex sample.
 */
size_t hostBytesPerSample(HostFormat f);

/**
 * @brief Full-scale magnitude of a host format.
 * @param f Host format.
 * @return 2^(n-1) for integer formats, 1.0 for float.
 */
double hostFullScale(HostFormat f);

/**
 * @brief Convert a VRT payload into the host format.
 * @param src Payload bytes.
 * @param wire Payload format.
 * @param swap Payload items are little-endian.
 * @param dst Destination buffer, at least nSamples * hostBytesPerSample().
 * @param host Destination format.
 * @param nSamples Complex samples to convert.
 * @param swapIq Exchange I and Q, for sources that send them in the other order.
 * @return Bytes written to @p dst.
 */
size_t wireToHost(const uint8_t *src, VRT::SampleFormat wire, bool swap,
                  uint8_t *dst, HostFormat host, size_t nSamples,
                  bool swapIq = false);

/**
 * @brief Convert host samples into a VRT payload.
 * @param src Host samples.
 * @param host Source format.
 * @param dst Destination buffer, at least payloadForSamples() bytes.
 * @param wire Payload format.
 * @param swap Emit payload items little-endian.
 * @param nSamples Complex samples to convert.
 * @param swapIq Exchange I and Q on the wire.
 * @return Bytes written to @p dst.
 */
size_t hostToWire(const uint8_t *src, HostFormat host,
                  uint8_t *dst, VRT::SampleFormat wire, bool swap,
                  size_t nSamples, bool swapIq = false);

/**
 * @brief Whole complex samples held by a payload.
 * @param nBytes Payload length in bytes.
 * @param wire Payload format.
 * @return Complex sample count.
 */
size_t samplesInPayload(size_t nBytes, VRT::SampleFormat wire);

/**
 * @brief Payload bytes needed to carry a number of complex samples.
 * @param nSamples Complex sample count.
 * @param wire Payload format.
 * @return Payload length in bytes.
 */
size_t payloadForSamples(size_t nSamples, VRT::SampleFormat wire);

} /* namespace Convert */
