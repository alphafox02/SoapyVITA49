/*
 * VITA 49.2 control plane: command packets and acknowledgements.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Control.hpp"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

namespace Control {

Session::Session() {}

Session::~Session() { close(); }

bool Session::open(const std::string &destAddr, uint16_t destPort,
                   uint32_t streamId, uint32_t controllerId,
                   bool swap, std::string &err)
{
    close();

    _destAddr     = destAddr;
    _destPort     = destPort;
    _streamId     = streamId;
    _controllerId = controllerId;
    _swap         = swap;
    _available    = false;

    _sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sock < 0) {
        err = std::string("control socket: ") + strerror(errno);
        return false;
    }

    /* Connecting a datagram socket fixes the peer so acknowledgements from
     * anywhere else are discarded by the kernel, and gives us a source port
     * the controllee can reply to. */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(destPort);
    if (inet_pton(AF_INET, destAddr.c_str(), &sa.sin_addr) != 1) {
        err = "control: cannot parse address " + destAddr;
        ::close(_sock);
        _sock = -1;
        return false;
    }

    if (connect(_sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        err = std::string("control connect: ") + strerror(errno);
        ::close(_sock);
        _sock = -1;
        return false;
    }

    return true;
}

void Session::close()
{
    if (_sock >= 0) {
        ::close(_sock);
        _sock = -1;
    }
    _available = false;
}

uint32_t Session::buildCam(bool queryState) const
{
    if (_camOverride)
        return _cam;

    uint32_t cam = CAM_CONTROLLEE_ENABLE;   /* 32-bit controllee ID follows */

    if (_controllerId != 0)
        cam |= CAM_CONTROLLER_ENABLE;

    if (queryState) {
        /* A query must not change anything, and the spec pairs no-action with
         * a query-state request and no execution or validation request. */
        cam |= ((uint32_t)ACTION_NONE << CAM_ACTION_SHIFT);
        cam |= CAM_REQ_QUERY_STATE;
    } else {
        cam |= ((uint32_t)_action << CAM_ACTION_SHIFT);
        cam |= CAM_PERMIT_WARNINGS | CAM_PERMIT_ERRORS;
        if (_requestAck)
            cam |= CAM_REQ_EXECUTION_ACK | CAM_REQ_WARNINGS | CAM_REQ_ERRORS;
    }

    return cam;
}

bool parseAck(const uint8_t *vrt, size_t len, bool swap, Ack *out)
{
    VRT::Header h;
    if (!VRT::parseHeader(vrt, len, swap, &h))
        return false;
    if (h.type != VRT::PKT_COMMAND && h.type != VRT::PKT_EXT_COMMAND)
        return false;

    uint32_t w0 = VRT::rd32(vrt, swap);
    out->isAck = (w0 & HDR_ACKNOWLEDGE) != 0;
    if (!out->isAck)
        return false;   /* a control packet echoed back is not an answer */

    size_t w = h.payloadOffset / 4;
    if (w + 2 > h.sizeWords)
        return false;

    uint32_t cam = VRT::rd32(vrt + w * 4, swap);
    w += 1;
    out->messageId = VRT::rd32(vrt + w * 4, swap);
    w += 1;

    out->partial     = (cam & CAM_PARTIAL_ACTION) != 0;
    out->hadWarnings = (cam & CAM_ACK_WARNINGS) != 0;
    out->hadErrors   = (cam & CAM_ACK_ERRORS) != 0;

    if (cam & CAM_CONTROLLEE_ENABLE)
        w += (cam & CAM_CONTROLLEE_UUID) ? 4 : 1;
    if (cam & CAM_CONTROLLER_ENABLE)
        w += (cam & CAM_CONTROLLER_UUID) ? 4 : 1;

    /* A query-state acknowledgement carries the controllee's current values in
     * the same encoding a context packet uses, so the shared walker reads
     * them. Errors and warnings, when present, occupy their own field arrays
     * ahead of nothing we need, and are reported through the flags above. */
    if (w < h.sizeWords)
        VRT::parseCIF0(vrt, h.sizeWords, w, swap, &out->fields);

    return true;
}

bool Session::exchange(const std::vector<uint8_t> &pkt, uint32_t messageId,
                       int timeoutMs, Ack *ack)
{
    if (_sock < 0) {
        _lastError = "control session not open";
        return false;
    }

    if (send(_sock, pkt.data(), pkt.size(), 0) != (ssize_t)pkt.size()) {
        _lastError = std::string("control send: ") + strerror(errno);
        return false;
    }
    _sent++;

    if (ack == nullptr || timeoutMs <= 0)
        return true;   /* fire and forget */

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint8_t buf[65536];
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)((now.tv_sec - t0.tv_sec) * 1000 +
                              (now.tv_nsec - t0.tv_nsec) / 1000000);
        long left = timeoutMs - elapsed;
        if (left <= 0)
            break;

        struct pollfd pfd;
        pfd.fd     = _sock;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, (int)left);
        if (pr <= 0)
            break;

        ssize_t n = recv(_sock, buf, sizeof(buf), 0);
        if (n <= 0)
            break;

        size_t vrtLen = 0;
        size_t off = VRT::vrlStrip(buf, (size_t)n, &vrtLen);

        Ack got;
        if (!parseAck(buf + off, vrtLen, _swap, &got))
            continue;
        /* Late acknowledgements for earlier commands can still be in flight,
         * so only the matching message ID ends the wait. */
        if (got.messageId != messageId)
            continue;

        *ack = got;
        _acks++;
        return true;
    }

    _lastError = "no acknowledgement within timeout";
    return false;
}

bool Session::probe(int timeoutMs, VRT::ContextInfo *current)
{
    if (_sock < 0)
        return false;

    /* Ask for the fields a Soapy client actually cares about. A 49.0 source
     * has no command packet handler at all and will simply not answer, which
     * is the signal that control is unavailable. */
    VRT::ContextInfo want;
    want.haveRfFreq     = true;
    want.haveSampleRate = true;
    want.haveBandwidth  = true;
    want.haveGain       = true;

    uint32_t messageId = _nextMessageId++;

    VRT::Builder b(_swap);
    b.begin(VRT::PKT_COMMAND, _count++);
    b.setStreamId(_streamId);
    b.appendWord(buildCam(true));
    b.appendWord(messageId);
    b.appendWord(_streamId);            /* controllee ID */
    if (_controllerId != 0)
        b.appendWord(_controllerId);

    /* A query sends the indicator bits with zeroed field bodies; the
     * controllee fills them in on the way back. */
    VRT::appendCIF0(b, want);
    const std::vector<uint8_t> &pkt = b.finish();

    Ack ack;
    if (!exchange(pkt, messageId, timeoutMs, &ack))
        return false;

    _available = !ack.hadErrors;
    if (current != nullptr)
        *current = ack.fields;
    return _available;
}

bool Session::setField(uint32_t cif0Bit, double value, int timeoutMs)
{
    if (_sock < 0)
        return false;

    VRT::ContextInfo set;
    switch (cif0Bit) {
    case VRT::CIF0_RF_REF_FREQ: set.haveRfFreq     = true; set.rfFreq     = value; break;
    case VRT::CIF0_SAMPLE_RATE: set.haveSampleRate = true; set.sampleRate = value; break;
    case VRT::CIF0_BANDWIDTH:   set.haveBandwidth  = true; set.bandwidth  = value; break;
    case VRT::CIF0_GAIN:        set.haveGain       = true; set.gainStage1 = value; break;
    default:
        _lastError = "unsupported control field";
        return false;
    }

    uint32_t messageId = _nextMessageId++;

    VRT::Builder b(_swap);
    b.begin(VRT::PKT_COMMAND, _count++);
    b.setStreamId(_streamId);
    b.appendWord(buildCam(false));
    b.appendWord(messageId);
    b.appendWord(_streamId);
    if (_controllerId != 0)
        b.appendWord(_controllerId);
    VRT::appendCIF0(b, set);
    const std::vector<uint8_t> &pkt = b.finish();

    if (!_requestAck)
        return exchange(pkt, messageId, 0, nullptr);

    Ack ack;
    if (!exchange(pkt, messageId, timeoutMs, &ack))
        return false;
    if (ack.hadErrors) {
        _lastError = "controllee reported an error";
        return false;
    }
    return true;
}

bool Session::query(uint32_t cif0Bits, int timeoutMs, VRT::ContextInfo *out)
{
    if (_sock < 0)
        return false;

    VRT::ContextInfo want;
    if (cif0Bits & VRT::CIF0_RF_REF_FREQ) want.haveRfFreq     = true;
    if (cif0Bits & VRT::CIF0_SAMPLE_RATE) want.haveSampleRate = true;
    if (cif0Bits & VRT::CIF0_BANDWIDTH)   want.haveBandwidth  = true;
    if (cif0Bits & VRT::CIF0_GAIN)        want.haveGain       = true;

    uint32_t messageId = _nextMessageId++;

    VRT::Builder b(_swap);
    b.begin(VRT::PKT_COMMAND, _count++);
    b.setStreamId(_streamId);
    b.appendWord(buildCam(true));
    b.appendWord(messageId);
    b.appendWord(_streamId);
    if (_controllerId != 0)
        b.appendWord(_controllerId);
    VRT::appendCIF0(b, want);
    const std::vector<uint8_t> &pkt = b.finish();

    Ack ack;
    if (!exchange(pkt, messageId, timeoutMs, &ack))
        return false;

    if (out != nullptr)
        *out = ack.fields;
    return !ack.hadErrors;
}

} /* namespace Control */
