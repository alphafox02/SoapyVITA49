/*
 * SoapySDR device for VITA 49 and VITA 49.2 streams.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "Control.hpp"
#include "Convert.hpp"
#include "Discovery.hpp"
#include "VRT.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <SoapySDR/Device.hpp>
#include <SoapySDR/Types.hpp>

/**
 * @file SoapyVITA49.hpp
 * @brief Device, stream and channel state for the VITA 49 driver.
 */

/**
 * @brief One unit of converted samples moving between a thread and the API.
 *
 * Carries a receiver thread's output to readStream(), or writeStream() output
 * to the transmit pacer. Blocks are recycled through a free list so that
 * steady-state streaming does not allocate.
 */
struct SampleBlock {
    std::vector<uint8_t> data;   /**< Storage, reused across blocks. */
    size_t    bytes   = 0;       /**< Valid bytes in data. */
    size_t    offset  = 0;       /**< Bytes already handed to the caller. */
    size_t    samples = 0;       /**< Complex samples, used by the transmit pacer. */
    long long timeNs  = 0;       /**< Time of the first sample. */
    bool      hasTime = false;   /**< timeNs is valid. */
    int       flags   = 0;       /**< SoapySDR stream flags for this block. */
};

/**
 * @brief Bounded queue of sample blocks backed by a free list.
 *
 * A full queue discards its oldest block and counts the loss. A UDP sender
 * will not slow down, so falling behind has to cost old data rather than
 * unbounded memory.
 */
class BlockQueue {
public:
    /**
     * @brief Construct a queue.
     * @param maxBlocks Blocks held before the oldest is discarded.
     */
    explicit BlockQueue(size_t maxBlocks = 256) : _max(maxBlocks) {}
    ~BlockQueue();

    /**
     * @brief Take a block from the free list, growing it if needed.
     * @param capacity Bytes the caller intends to write.
     * @return Block owned by the caller until publish() or release().
     */
    SampleBlock *acquire(size_t capacity);

    /**
     * @brief Hand a block to the consumer, discarding the oldest if full.
     * @param b Block previously returned by acquire().
     */
    void publish(SampleBlock *b);

    /**
     * @brief Wait for the head of the queue.
     * @param timeoutUs Time to wait; 0 polls.
     * @return Head block, still owned by the queue, or null on timeout.
     */
    SampleBlock *waitReady(long timeoutUs);

    /** @brief Head of the queue without waiting, or null when empty. */
    SampleBlock *peekReady();

    /** @brief Retire the head of the queue to the free list. */
    void popReady();

    /** @brief Return an unpublished block to the free list. */
    void release(SampleBlock *b);

    /** @brief Retire every queued block. */
    void flush();

    /** @brief Wake any thread waiting in waitReady(). */
    void wake();

    /** @brief Blocks discarded because the queue was full. */
    uint64_t dropped() const { return _dropped.load(std::memory_order_relaxed); }

    /** @brief Reset the discard counter. */
    void clearDropped() { _dropped.store(0, std::memory_order_relaxed); }

    /** @brief Blocks currently waiting for the consumer. */
    size_t readyCount();

private:
    std::mutex               _mtx;
    std::condition_variable  _cv;
    std::deque<SampleBlock*> _ready;
    std::vector<SampleBlock*> _free;
    size_t                   _max;
    std::atomic<uint64_t>    _dropped{0};
};

/** @brief Per-channel receive state. */
struct RxChannel {
    std::string  bindAddr = "0.0.0.0";
    uint16_t     port     = 4991;
    uint32_t     streamId = 0;
    bool         anyStreamId = true;   /* accept every SID on this port */
    bool         hdrSwap  = false;
    bool         dataSwap = false;
    bool         iqSwap   = false;   /**< Source sends Q before I. */
    VRT::SampleFormat wireFormat = VRT::FMT_CI16;
    bool         wireFormatLocked = false;   /* set by the format= argument */

    /* Metadata, seeded from discovery and refreshed by context packets. */
    std::atomic<double> sampleRate{0.0};
    std::atomic<double> centerFreq{0.0};
    std::atomic<double> bandwidth{0.0};
    std::atomic<double> gain{0.0};
    std::atomic<double> refLevel{0.0};

    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> gaps{0};
    std::atomic<uint64_t> overRange{0};
    std::atomic<long long> lastTimeNs{0};

    uint8_t  lastCount   = 0;
    bool     haveCount   = false;
    bool     endianChecked = false; /**< Byte-order cross-check already run. */

    std::unique_ptr<BlockQueue> queue;
};

/** @brief Per-channel transmit state. */
struct TxChannel {
    std::string destAddr = "127.0.0.1";
    uint16_t    destPort = 4991;
    uint32_t    streamId = 0;
    bool        hdrSwap  = false;
    bool        dataSwap = false;
    bool        iqSwap   = false;   /**< Emit Q before I. */
    VRT::SampleFormat wireFormat = VRT::FMT_CI16;
    size_t      mtu      = 1472;      /* UDP payload budget */

    std::atomic<double> sampleRate{1.0e6};
    std::atomic<double> centerFreq{0.0};
    std::atomic<double> bandwidth{0.0};
    std::atomic<double> gain{0.0};

    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> underflows{0};

    int      sock = -1;
    uint8_t  count = 0;
    uint8_t  ctxCount = 0;
    /* Rate limiter for send-failure reporting, monotonic nanoseconds. */
    long long nextSendReportNs = 0;

    std::unique_ptr<BlockQueue> queue;
};

/**
 * @brief A bound UDP socket and the thread draining it.
 *
 * Several channels share one endpoint when a port carries multiple streams,
 * because a port can only be bound once.
 */
struct RxEndpoint {
    std::string bindAddr;
    uint16_t    port = 0;
    int         sock = -1;
    std::thread thread;
    std::atomic<bool> run{false};
    std::vector<size_t> channels;    /* indices into the device's rx list */
};

/** @brief Stream state, returned to SoapySDR as an opaque pointer. */
struct StreamHandle {
    int    direction = 0;
    Convert::HostFormat hostFormat = Convert::HOST_CF32;
    std::vector<size_t> channels;
    bool   active = false;
    size_t mtuSamples = 4096;
};

class SoapyVITA49 : public SoapySDR::Device {
public:
    explicit SoapyVITA49(const SoapySDR::Kwargs &args);
    ~SoapyVITA49() override;

    /* Identification */
    std::string getDriverKey() const override;
    std::string getHardwareKey() const override;
    SoapySDR::Kwargs getHardwareInfo() const override;

    /* Channels */
    size_t getNumChannels(const int direction) const override;
    bool getFullDuplex(const int direction, const size_t channel) const override;

    /* Stream API */
    std::vector<std::string> getStreamFormats(const int direction,
                                              const size_t channel) const override;
    std::string getNativeStreamFormat(const int direction, const size_t channel,
                                      double &fullScale) const override;
    SoapySDR::ArgInfoList getStreamArgsInfo(const int direction,
                                            const size_t channel) const override;

    SoapySDR::Stream *setupStream(const int direction, const std::string &format,
                                  const std::vector<size_t> &channels,
                                  const SoapySDR::Kwargs &args) override;
    void closeStream(SoapySDR::Stream *stream) override;
    size_t getStreamMTU(SoapySDR::Stream *stream) const override;

    int activateStream(SoapySDR::Stream *stream, const int flags,
                       const long long timeNs, const size_t numElems) override;
    int deactivateStream(SoapySDR::Stream *stream, const int flags,
                         const long long timeNs) override;

    int readStream(SoapySDR::Stream *stream, void *const *buffs,
                   const size_t numElems, int &flags, long long &timeNs,
                   const long timeoutUs) override;
    int writeStream(SoapySDR::Stream *stream, const void *const *buffs,
                    const size_t numElems, int &flags, const long long timeNs,
                    const long timeoutUs) override;
    int readStreamStatus(SoapySDR::Stream *stream, size_t &chanMask, int &flags,
                         long long &timeNs, const long timeoutUs) override;

    /* Antennas - a network stream has exactly one notional input */
    std::vector<std::string> listAntennas(const int direction,
                                          const size_t channel) const override;
    void setAntenna(const int direction, const size_t channel,
                    const std::string &name) override;
    std::string getAntenna(const int direction, const size_t channel) const override;

    /* Gain */
    std::vector<std::string> listGains(const int direction,
                                       const size_t channel) const override;
    bool hasGainMode(const int direction, const size_t channel) const override;
    void setGain(const int direction, const size_t channel,
                 const double value) override;
    double getGain(const int direction, const size_t channel) const override;
    SoapySDR::Range getGainRange(const int direction,
                                 const size_t channel) const override;

    /* Frequency */
    void setFrequency(const int direction, const size_t channel,
                      const std::string &name, const double frequency,
                      const SoapySDR::Kwargs &args) override;
    double getFrequency(const int direction, const size_t channel,
                        const std::string &name) const override;
    std::vector<std::string> listFrequencies(const int direction,
                                             const size_t channel) const override;
    SoapySDR::RangeList getFrequencyRange(const int direction, const size_t channel,
                                          const std::string &name) const override;
    SoapySDR::ArgInfoList getFrequencyArgsInfo(const int direction,
                                               const size_t channel) const override;

    /* Sample rate and bandwidth */
    void setSampleRate(const int direction, const size_t channel,
                       const double rate) override;
    double getSampleRate(const int direction, const size_t channel) const override;
    std::vector<double> listSampleRates(const int direction,
                                        const size_t channel) const override;
    SoapySDR::RangeList getSampleRateRange(const int direction,
                                           const size_t channel) const override;
    void setBandwidth(const int direction, const size_t channel,
                      const double bw) override;
    double getBandwidth(const int direction, const size_t channel) const override;
    SoapySDR::RangeList getBandwidthRange(const int direction,
                                          const size_t channel) const override;

    /* Time */
    std::vector<std::string> listTimeSources() const override;
    std::string getTimeSource() const override;
    bool hasHardwareTime(const std::string &what) const override;
    long long getHardwareTime(const std::string &what) const override;

    /* Settings */
    SoapySDR::ArgInfoList getSettingInfo() const override;
    void writeSetting(const std::string &key, const std::string &value) override;
    std::string readSetting(const std::string &key) const override;

    /**
     * @brief Enumerate available streams.
     * @param args Filter, which may name an address, port or stream identifier.
     * @return One entry per stream, each sufficient to open it with make().
     */
    static SoapySDR::KwargsList find(const SoapySDR::Kwargs &args);

    /**
     * @brief Construct a device.
     * @param args Arguments as returned by find(), possibly extended.
     * @return Device owned by the caller.
     */
    static SoapySDR::Device *make(const SoapySDR::Kwargs &args);

private:
    /** @brief Build receive channels from device arguments. */
    void configureRx(const SoapySDR::Kwargs &args);

    /** @brief Build transmit channels from device arguments. */
    void configureTx(const SoapySDR::Kwargs &args);

    /** @brief Bind one socket per distinct receive endpoint. */
    bool openEndpoints(std::string &err);

    /** @brief Stop receiver threads and close their sockets. */
    void closeEndpoints();

    /** @brief Receive thread body for one endpoint. */
    void receiverLoop(RxEndpoint *ep);

    /** @brief Decode one datagram and queue its samples or apply its metadata. */
    void handleRxPacket(RxEndpoint *ep, const uint8_t *pkt, size_t len);

    /**
     * @brief Find the channel a packet belongs to.
     * @param ep Endpoint the packet arrived on.
     * @param sid Stream identifier from the packet.
     * @param hasSid Packet class carries a stream identifier.
     * @return Matching channel, a wildcard channel, or null.
     */
    RxChannel *rxChannelForStream(RxEndpoint *ep, uint32_t sid, bool hasSid);

    /** @brief Open one connected socket per transmit channel. */
    bool openTxSockets(std::string &err);

    /** @brief Stop transmit threads and close their sockets. */
    void closeTxSockets();

    /** @brief Transmit pacer body for one channel. */
    void transmitterLoop(size_t chIdx);

    /** @brief Emit one context packet describing a transmit channel. */
    void sendContextPacket(size_t chIdx);

    /**
     * @brief Route a parameter change through the control path.
     *
     * Sends a command packet when the controllee answered the probe, and
     * commits only on a clean acknowledgement. Otherwise records the value
     * locally and warns once, so the host sees a consistent device.
     *
     * @param direction SOAPY_SDR_RX or SOAPY_SDR_TX.
     * @param channel Channel index.
     * @param cif0Bit Field to set.
     * @param value New value in natural units.
     * @param what Name of the operation, used in the warning.
     * @return True if the controllee applied the change.
     */
    bool applyControl(int direction, size_t channel, uint32_t cif0Bit,
                      double value, const char *what);

    std::vector<std::unique_ptr<RxChannel>> _rx;
    std::vector<std::unique_ptr<TxChannel>> _tx;
    std::vector<std::unique_ptr<RxEndpoint>> _endpoints;

    std::vector<std::thread>       _txThreads;
    std::atomic<bool>              _txRun{false};

    Convert::HostFormat _rxHostFormat = Convert::HOST_CF32;
    Convert::HostFormat _txHostFormat = Convert::HOST_CF32;

    std::unique_ptr<Control::Session> _control;
    bool _controlWarned = false;

    mutable std::mutex _mtx;

    std::string _label;
    std::string _serial;
    size_t      _rxBufferBlocks = 512;
    int         _socketRcvBuf   = 16 * 1024 * 1024;
    double      _contextPeriodSec = 1.0;
    bool        _emitTxContext  = true;
    /* Correction applied to every VRT timestamp. A source whose clock was
     * never set has a large constant error that the stream itself does not
     * report, so it has to come from here. */
    std::atomic<long long> _timeOffsetNs{0};
    bool        _timeAuto       = false;   /* measure the offset from the first packet */
    bool        _timeUseHost    = false;   /* ignore stream time, stamp on arrival */
    std::atomic<bool> _timeMeasured{false};
    /* Permit a second receiver on the same unicast port. Off by default:
     * the second binder silently takes the traffic from the first. */
    bool        _allowPortReuse = false;
    bool        _forceCf32Time  = false;
};
