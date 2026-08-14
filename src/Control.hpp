/*
 * VITA 49.2 control plane: command packets and acknowledgements.
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
 * @file Control.hpp
 * @brief Setting and querying source parameters over VITA 49.2.
 *
 * A command packet body follows the usual prologue with the Control and
 * Acknowledge Mode word, a message identifier, optional controllee and
 * controller identifiers of one word each or four for a UUID, then CIF0 and
 * its fields (section 8.1). Fields are encoded exactly as in a context packet,
 * so both share one walker and one builder.
 *
 * VITA 49.0 sources have no command handler and simply do not answer, which is
 * how the absence of a control path is detected.
 *
 * TODO: no controllee implementing command packets has answered this code. The
 * packet layout follows the standard and agrees with published implementations,
 * but it has never completed an exchange with a real device.
 */

namespace Control {

/**
 * @brief Control and Acknowledge Mode bits (sections 8.2.1, 8.3.1 and 8.4.1).
 *
 * A controllee implementing an adjusted profile may differ, so the computed
 * word can be replaced at runtime through Session::setCamOverride().
 */
enum CAMBit {
    CAM_CONTROLLEE_ENABLE  = 1u << 31, /**< Controllee identifier present. */
    CAM_CONTROLLEE_UUID    = 1u << 30, /**< Controllee identifier is a 128-bit UUID. */
    CAM_CONTROLLER_ENABLE  = 1u << 29, /**< Controller identifier present. */
    CAM_CONTROLLER_UUID    = 1u << 28, /**< Controller identifier is a 128-bit UUID. */
    CAM_PERMIT_PARTIAL     = 1u << 27, /**< Partial execution permitted. */
    CAM_PERMIT_WARNINGS    = 1u << 26, /**< Execution permitted despite warnings. */
    CAM_PERMIT_ERRORS      = 1u << 25, /**< Execution permitted despite errors. */
    CAM_ACTION_SHIFT       = 23,       /**< Action mode, 2 bits at 24:23. */
    CAM_NACK_ONLY          = 1u << 22, /**< Acknowledge only on warning or error. */
    CAM_REQ_VALIDATION_ACK = 1u << 20, /**< Request a validation acknowledgement. */
    CAM_REQ_EXECUTION_ACK  = 1u << 19, /**< Request an execution acknowledgement. */
    CAM_REQ_QUERY_STATE    = 1u << 18, /**< Request current state in the reply. */
    CAM_REQ_WARNINGS       = 1u << 17, /**< Request warning reporting. */
    CAM_REQ_ERRORS         = 1u << 16, /**< Request error reporting. */
    CAM_TSC_SHIFT          = 12,       /**< Timestamp control, 3 bits at 14:12. */
    CAM_PARTIAL_ACTION     = 1u << 11, /**< Acknowledgement: action was partial. */
    CAM_SCHEDULED_EXECUTED = 1u << 10, /**< Acknowledgement: scheduled or executed. */
};

/** @brief Action mode, CAM bits 24:23. */
enum ActionMode {
    ACTION_NONE    = 0, /**< Take no action; pairs with a query. */
    ACTION_DRY_RUN = 1, /**< Validate without applying. */
    ACTION_EXECUTE = 2, /**< Apply the request. */
};

/** @brief Command header bit 26: the packet is an acknowledgement. */
static const uint32_t HDR_ACKNOWLEDGE = 1u << 26;

/** @brief Command header bit 24: the packet cancels a scheduled command. */
static const uint32_t HDR_CANCEL = 1u << 24;

/** @name Acknowledgements reuse the request bit positions to report outcome. */
/**@{*/
static const uint32_t CAM_ACK_VALIDATION = CAM_REQ_VALIDATION_ACK;
static const uint32_t CAM_ACK_EXECUTION  = CAM_REQ_EXECUTION_ACK;
static const uint32_t CAM_ACK_QUERY      = CAM_REQ_QUERY_STATE;
static const uint32_t CAM_ACK_WARNINGS   = CAM_REQ_WARNINGS;
static const uint32_t CAM_ACK_ERRORS     = CAM_REQ_ERRORS;
/**@}*/

/** @brief Decoded acknowledgement packet. */
struct Ack {
    uint32_t messageId   = 0;     /**< Identifier of the command being answered. */
    bool     isAck       = false; /**< Header bit 26 was set. */
    bool     partial     = false; /**< Only part of the request was applied. */
    bool     hadWarnings = false; /**< Controllee reported warnings. */
    bool     hadErrors   = false; /**< Controllee reported errors. */
    VRT::ContextInfo fields;      /**< Values returned by a query. */
};

/**
 * @brief A control association with one controllee.
 *
 * Owns a UDP socket connected to the controllee, so acknowledgements from any
 * other peer are discarded by the kernel and the controllee has a source port
 * to reply to.
 */
class Session {
public:
    Session();
    ~Session();

    /**
     * @brief Open the association.
     *
     * Creating the socket says nothing about reachability; use probe() to
     * establish whether the controllee answers.
     *
     * @param destAddr Controllee address.
     * @param destPort Controllee command port.
     * @param streamId Stream to control, used as the controllee identifier.
     * @param controllerId Controller identifier, or 0 to omit it.
     * @param swap Emit and read 32-bit words little-endian.
     * @param[out] err Reason the socket could not be opened.
     * @return False if the socket could not be created or connected.
     */
    bool open(const std::string &destAddr, uint16_t destPort,
              uint32_t streamId, uint32_t controllerId,
              bool swap, std::string &err);

    /** @brief Close the association and mark control unavailable. */
    void close();

    /**
     * @brief Send a query-state command and wait for an acknowledgement.
     *
     * This is the capability test. A source without a command handler does not
     * answer, and the timeout is what marks control unavailable.
     *
     * @param timeoutMs Time to wait for the acknowledgement.
     * @param[out] current Values the controllee reported, may be null.
     * @return True if the controllee answered without errors.
     */
    bool probe(int timeoutMs, VRT::ContextInfo *current);

    /**
     * @brief Set one CIF0 field.
     * @param cif0Bit One of CIF0_RF_REF_FREQ, CIF0_SAMPLE_RATE,
     *        CIF0_BANDWIDTH or CIF0_GAIN.
     * @param value New value in natural units.
     * @param timeoutMs Time to wait for the acknowledgement.
     * @return True when the controllee acknowledged without errors, or when
     *         acknowledgements are disabled and the datagram was sent.
     */
    bool setField(uint32_t cif0Bit, double value, int timeoutMs);

    /**
     * @brief Query one or more CIF0 fields.
     * @param cif0Bits Fields to request, as a mask of CIF0Bit values.
     * @param timeoutMs Time to wait for the acknowledgement.
     * @param[out] out Values the controllee reported, may be null.
     * @return True if the controllee answered without errors.
     */
    bool query(uint32_t cif0Bits, int timeoutMs, VRT::ContextInfo *out);

    /** @brief Whether the controllee has answered a probe. */
    bool available() const { return _available; }

    /**
     * @brief Replace the computed CAM word.
     * @param on Use @p cam instead of the computed value.
     * @param cam Raw CAM word.
     */
    void setCamOverride(bool on, uint32_t cam) { _camOverride = on; _cam = cam; }

    /** @brief Set the action mode used by setField(). */
    void setActionMode(ActionMode m) { _action = m; }

    /** @brief Request acknowledgements for commands that change state. */
    void setRequestAck(bool on) { _requestAck = on; }

    /** @brief Text of the most recent failure. */
    const std::string &lastError() const { return _lastError; }

    /** @brief Commands sent since the session opened. */
    uint64_t commandsSent() const { return _sent; }

    /** @brief Acknowledgements matched since the session opened. */
    uint64_t acksReceived() const { return _acks; }

private:
    uint32_t buildCam(bool queryState) const;
    bool exchange(const std::vector<uint8_t> &pkt, uint32_t messageId,
                  int timeoutMs, Ack *ack);

    int         _sock = -1;
    std::string _destAddr;
    uint16_t    _destPort = 0;
    uint32_t    _streamId = 0;
    uint32_t    _controllerId = 0;
    bool        _swap = false;
    bool        _available = false;
    bool        _requestAck = true;
    bool        _camOverride = false;
    uint32_t    _cam = 0;
    ActionMode  _action = ACTION_EXECUTE;
    uint32_t    _nextMessageId = 1;
    uint8_t     _count = 0;
    uint64_t    _sent = 0;
    uint64_t    _acks = 0;
    std::string _lastError;
};

/**
 * @brief Decode a command packet as an acknowledgement.
 * @param vrt Start of the VRT packet.
 * @param len Bytes available from @p vrt.
 * @param swap Read 32-bit words little-endian.
 * @param[out] out Decoded acknowledgement.
 * @return False if the packet is not a command packet, or is a control rather
 *         than an acknowledgement.
 */
bool parseAck(const uint8_t *vrt, size_t len, bool swap, Ack *out);

} /* namespace Control */
