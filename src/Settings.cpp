/*
 * Device construction, metadata and parameter control.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "SoapyVITA49.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <SoapySDR/Formats.hpp>
#include <SoapySDR/Logger.hpp>

namespace {

std::string argOr(const SoapySDR::Kwargs &a, const std::string &k,
                  const std::string &d)
{
    auto it = a.find(k);
    return (it == a.end()) ? d : it->second;
}

bool argFlag(const SoapySDR::Kwargs &a, const std::string &k, bool d)
{
    auto it = a.find(k);
    if (it == a.end())
        return d;
    const std::string &v = it->second;
    return !(v == "0" || v == "false" || v == "no" || v == "off");
}

double argNum(const SoapySDR::Kwargs &a, const std::string &k, double d)
{
    auto it = a.find(k);
    return (it == a.end()) ? d : atof(it->second.c_str());
}

/* "big"/"be"/"msb" mean spec order; "little"/"le"/"lsb" mean byte swapped. */
bool parseEndian(const std::string &v, bool dflt)
{
    if (v == "little" || v == "le" || v == "lsb") return true;
    if (v == "big" || v == "be" || v == "msb")    return false;
    return dflt;
}

VRT::SampleFormat parseWireFormat(const std::string &v)
{
    if (v == "ci8"  || v == "cs8"  || v == "sc8")  return VRT::FMT_CI8;
    if (v == "ci12" || v == "cs12" || v == "sc12") return VRT::FMT_CI12;
    if (v == "ci16" || v == "cs16" || v == "sc16") return VRT::FMT_CI16;
    if (v == "cf32" || v == "fc32")                return VRT::FMT_CF32;
    return VRT::FMT_UNKNOWN;
}

} /* anonymous namespace */

/* ------------------------------------------------------------------ */
/* Construction                                                       */
/* ------------------------------------------------------------------ */

SoapyVITA49::SoapyVITA49(const SoapySDR::Kwargs &args)
{
    _label  = argOr(args, "label", "VITA-49");
    _rxBufferBlocks   = (size_t)argNum(args, "buffers", 512);
    _socketRcvBuf     = (int)argNum(args, "rcvbuf", 16 * 1024 * 1024);
    _contextPeriodSec = argNum(args, "context_rate", 1.0);

    /* gain_range=min:max[:step], the gain values the source accepts */
    if (args.count("gain_range")) {
        double lo = 0, hi = 0, step = 0;
        int n = sscanf(args.at("gain_range").c_str(), "%lf:%lf:%lf", &lo, &hi, &step);
        if (n < 2 || !(hi > lo))
            throw std::invalid_argument("gain_range must be min:max or min:max:step");
        _gainRange = SoapySDR::Range(lo, hi, n == 3 ? step : 0.0);
        _haveGainRange = true;
    }
    _emitTxContext    = argFlag(args, "tx_context", true);
    _allowPortReuse   = argFlag(args, "reuse", false);

    /* time_source: stream uses the timestamps as sent, host ignores them and
     * stamps on arrival, auto keeps the stream's precision but corrects its
     * epoch from the first packet. time_offset adds a fixed number of seconds
     * on top of whichever is chosen. */
    const std::string timeSrc = argOr(args, "time_source", "stream");
    _timeUseHost = (timeSrc == "host");
    _timeAuto    = (timeSrc == "auto");
    _timeOffsetNs.store((long long)(argNum(args, "time_offset", 0.0) * 1e9));

    configureRx(args);
    configureTx(args);

    /*
     * Bring up the control association. A VITA 49.0 source has no command
     * packet handler, so the probe simply times out and every later set call
     * becomes local bookkeeping with a single warning. Nothing here fails the
     * device open, because receiving is useful with or without control.
     */
    const std::string ctrlMode = argOr(args, "control", "auto");
    if (ctrlMode != "off" && !_rx.empty()) {
        std::string ctrlAddr = argOr(args, "ctrl_addr", argOr(args, "source", ""));
        if (ctrlAddr.empty() || ctrlAddr == "0.0.0.0")
            ctrlAddr = argOr(args, "addr", "");

        uint16_t ctrlPort = (uint16_t)argNum(args, "ctrl_port", _rx[0]->port);

        if (!ctrlAddr.empty() && ctrlAddr != "0.0.0.0") {
            _control.reset(new Control::Session());
            std::string err;
            if (!_control->open(ctrlAddr, ctrlPort, _rx[0]->streamId,
                                (uint32_t)argNum(args, "controller_id", 0),
                                _rx[0]->hdrSwap, err)) {
                SoapySDR::logf(SOAPY_SDR_WARNING, "vita49: %s", err.c_str());
                _control.reset();
            } else {
                if (args.count("ctrl_cam"))
                    _control->setCamOverride(true,
                        (uint32_t)strtoul(args.at("ctrl_cam").c_str(), nullptr, 0));

                /* Dry run asks the controllee to validate a command without
                 * applying it, which is how to test a control path without
                 * moving a receiver that is in use. */
                if (argFlag(args, "ctrl_dry_run", false))
                    _control->setActionMode(Control::ACTION_DRY_RUN);
                _control->setRequestAck(argFlag(args, "ctrl_ack", true));

                double timeout = argNum(args, "ctrl_timeout", 500);
                if (!std::isfinite(timeout) || timeout < 1 || timeout > 300000)
                    throw std::invalid_argument("ctrl_timeout must be 1..300000 milliseconds");
                _controlTimeoutMs = (int)timeout;
                VRT::ContextInfo cur;
                if (_control->probe(_controlTimeoutMs, &cur)) {
                    SoapySDR::logf(SOAPY_SDR_INFO,
                        "vita49: VITA 49.2 control available at %s:%u",
                        ctrlAddr.c_str(), ctrlPort);
                    /* A query-state acknowledgement is authoritative, so let
                     * it correct whatever discovery guessed. */
                    if (cur.haveRfFreq)     _rx[0]->centerFreq = cur.rfFreq;
                    if (cur.haveSampleRate) _rx[0]->sampleRate = cur.sampleRate;
                    if (cur.haveBandwidth)  _rx[0]->bandwidth  = cur.bandwidth;
                    if (cur.haveGain)       _rx[0]->gain = cur.gainStage1 + cur.gainStage2;
                    /* AGC/MGC is asked separately: a controllee that does not
                     * know the State/Event field may reject the query, and
                     * that must not cost the control path itself. */
                    VRT::ContextInfo se;
                    if (_control->query(VRT::CIF0_STATE_EVENT, _controlTimeoutMs, &se) &&
                        se.haveAgcMode)
                        _rx[0]->agcMode = se.agcAuto ? 1 : 0;
                } else if (ctrlMode == "on") {
                    SoapySDR::logf(SOAPY_SDR_ERROR,
                        "vita49: control=on but %s:%u did not acknowledge a "
                        "query-state command", ctrlAddr.c_str(), ctrlPort);
                } else {
                    SoapySDR::logf(SOAPY_SDR_INFO,
                        "vita49: no VITA 49.2 acknowledgement from %s:%u, "
                        "running receive-only", ctrlAddr.c_str(), ctrlPort);
                }
            }
        }
    }

    char ser[64];
    snprintf(ser, sizeof(ser), "%s:%u/%08x",
             _rx.empty() ? "tx" : _rx[0]->bindAddr.c_str(),
             _rx.empty() ? 0 : _rx[0]->port,
             _rx.empty() ? 0 : _rx[0]->streamId);
    _serial = ser;
}

SoapyVITA49::~SoapyVITA49()
{
    closeEndpoints();
    closeTxSockets();
    if (_control)
        _control->close();
}

void SoapyVITA49::configureRx(const SoapySDR::Kwargs &args)
{
    if (!argFlag(args, "rx", true))
        return;

    const std::string addr = argOr(args, "addr", "0.0.0.0");
    const uint16_t port = (uint16_t)argNum(args, "port", 4991);
    const std::string sidArg = argOr(args, "sid", "any");

    bool hdrSwap  = parseEndian(argOr(args, "hdr_endian", "big"), false);
    /* A source that byte-swaps its headers almost always byte-swaps its
     * samples too, so data order follows header order unless set explicitly. */
    bool dataSwap = parseEndian(argOr(args, "data_endian", hdrSwap ? "little" : "big"),
                                hdrSwap);

    /* Some sources place Q ahead of I, which mirrors the spectrum unless it is
     * undone here. */
    const bool iqSwap = argFlag(args, "iq_swap", false);

    VRT::SampleFormat wire = parseWireFormat(argOr(args, "format", ""));
    bool wireLocked = (wire != VRT::FMT_UNKNOWN);
    if (!wireLocked)
        wire = VRT::FMT_CI16;

    /*
     * Channel layout. One stream ID per channel is the default because that is
     * what makes each stream appear as its own device in a host that offers no
     * channel selector. Asking for sid=all instead collapses every stream on
     * the port into one multi-channel device, which suits GNU Radio.
     */
    /*
     * One entry per channel. Streams multiplexed on a single port can differ
     * in rate and payload format, so each channel carries its own metadata
     * rather than inheriting one set of device arguments.
     */
    std::vector<Discovery::StreamInfo> chans;
    bool anySid = false;

    if (sidArg == "all") {
        std::vector<Discovery::StreamInfo> found;
        std::string err;
        int dwell = (int)argNum(args, "dwell", 1500);
        if (Discovery::probeEndpoint(addr, port, dwell, found, err)) {
            for (const auto &s : found)
                if (s.dstPort == port && s.hasStreamId)
                    chans.push_back(s);
        }
        std::sort(chans.begin(), chans.end(),
                  [](const Discovery::StreamInfo &a, const Discovery::StreamInfo &b) {
                      return a.streamId < b.streamId;
                  });
        chans.erase(std::unique(chans.begin(), chans.end(),
                    [](const Discovery::StreamInfo &a, const Discovery::StreamInfo &b) {
                        return a.streamId == b.streamId;
                    }), chans.end());

        if (chans.empty()) {
            SoapySDR::logf(SOAPY_SDR_WARNING,
                "vita49: sid=all found no streams on %s:%u, falling back to "
                "a single channel accepting any stream ID", addr.c_str(), port);
            anySid = true;
            chans.resize(1);
        } else {
            /* readStream has to hand every channel the same element count, so
             * streams of unequal rate cannot be read in lockstep: the fastest
             * ends up throttled to the slowest and drops the difference. */
            double r0 = chans.front().sampleRate;
            for (const auto &s : chans) {
                if (r0 > 0.0 && s.sampleRate > 0.0 && s.sampleRate != r0) {
                    SoapySDR::logf(SOAPY_SDR_WARNING,
                        "vita49: streams on %s:%u have different sample rates "
                        "(%.0f and %.0f Hz); a combined multi-channel stream "
                        "runs at the slowest and drops the rest, so open them "
                        "as separate devices instead",
                        addr.c_str(), port, r0, s.sampleRate);
                    break;
                }
            }
        }
    } else if (sidArg == "any" || sidArg == "none" || sidArg.empty()) {
        anySid = true;
        chans.resize(1);
    } else {
        Discovery::StreamInfo s;
        s.hasStreamId = true;
        s.streamId    = (uint32_t)strtoul(sidArg.c_str(), nullptr, 0);
        chans.push_back(s);
    }

    size_t nchan = (size_t)argNum(args, "nchan", (double)chans.size());
    nchan = std::max<size_t>(1, std::min(nchan, chans.size()));

    for (size_t i = 0; i < nchan; i++) {
        const Discovery::StreamInfo &info = chans[i];

        std::unique_ptr<RxChannel> ch(new RxChannel());
        ch->bindAddr    = addr;
        ch->port        = port;
        ch->streamId    = info.streamId;
        ch->anyStreamId = anySid;
        ch->hdrSwap     = hdrSwap;
        ch->dataSwap    = dataSwap;
        ch->iqSwap      = iqSwap;
        ch->queue.reset(new BlockQueue(_rxBufferBlocks));

        /* An explicit format argument applies to every channel; otherwise each
         * channel starts from whatever discovery saw and is corrected by the
         * next context packet. */
        if (wireLocked) {
            ch->wireFormat       = wire;
            ch->wireFormatLocked = true;
        } else {
            ch->wireFormat       = (info.format != VRT::FMT_UNKNOWN)
                                 ? info.format : VRT::FMT_CI16;
            ch->wireFormatLocked = false;
        }

        ch->sampleRate = (info.sampleRate > 0.0) ? info.sampleRate
                                                 : argNum(args, "rate", 0.0);
        ch->centerFreq = (info.rfFreq > 0.0) ? info.rfFreq
                                             : argNum(args, "freq", 0.0);
        ch->bandwidth  = (info.bandwidth > 0.0) ? info.bandwidth
                                                : argNum(args, "bandwidth", 0.0);

        _rx.push_back(std::move(ch));
    }
}

void SoapyVITA49::configureTx(const SoapySDR::Kwargs &args)
{
    /* Transmit needs an explicit destination: there is nothing to discover,
     * because a receiver that is not yet streaming emits nothing to find. */
    const std::string dest = argOr(args, "tx_addr", "");
    if (dest.empty() || !argFlag(args, "tx", true))
        return;

    bool hdrSwap  = parseEndian(argOr(args, "tx_hdr_endian",
                                      argOr(args, "hdr_endian", "big")), false);
    bool dataSwap = parseEndian(argOr(args, "tx_data_endian",
                                      argOr(args, "data_endian",
                                            hdrSwap ? "little" : "big")), hdrSwap);

    VRT::SampleFormat wire = parseWireFormat(argOr(args, "tx_format",
                                                   argOr(args, "format", "ci16")));
    if (wire == VRT::FMT_UNKNOWN)
        wire = VRT::FMT_CI16;

    size_t nchan = (size_t)std::max(1.0, argNum(args, "tx_nchan", 1));
    uint32_t baseSid = (uint32_t)strtoul(
        argOr(args, "tx_sid", "0x1").c_str(), nullptr, 0);

    for (size_t i = 0; i < nchan; i++) {
        std::unique_ptr<TxChannel> ch(new TxChannel());
        ch->destAddr   = dest;
        ch->destPort   = (uint16_t)argNum(args, "tx_port", 4991);
        ch->streamId   = baseSid + (uint32_t)i;
        ch->hdrSwap    = hdrSwap;
        ch->dataSwap   = dataSwap;
        ch->iqSwap     = argFlag(args, "tx_iq_swap", argFlag(args, "iq_swap", false));
        ch->wireFormat = wire;
        ch->mtu        = (size_t)argNum(args, "mtu", 1472);
        ch->sampleRate = argNum(args, "tx_rate", argNum(args, "rate", 1.0e6));
        ch->centerFreq = argNum(args, "tx_freq", argNum(args, "freq", 0.0));
        ch->queue.reset(new BlockQueue(_rxBufferBlocks));
        _tx.push_back(std::move(ch));
    }
}

/* ------------------------------------------------------------------ */
/* Identification                                                     */
/* ------------------------------------------------------------------ */

std::string SoapyVITA49::getDriverKey() const { return "vita49"; }

std::string SoapyVITA49::getHardwareKey() const
{
    return (_control && _control->available()) ? "VITA-49.2" : "VITA-49";
}

SoapySDR::Kwargs SoapyVITA49::getHardwareInfo() const
{
    SoapySDR::Kwargs info;
    info["origin"]  = "https://github.com/alphafox02/SoapyVITA49";
    info["serial"]  = _serial;
    info["label"]   = _label;
    info["control"] = (_control && _control->available()) ? "vita49.2" : "none";

    if (!_rx.empty()) {
        const RxChannel *c = _rx[0].get();
        info["rx_endpoint"]  = c->bindAddr + ":" + std::to_string(c->port);
        info["rx_format"]    = VRT::formatName(c->wireFormat);
        info["hdr_endian"]   = c->hdrSwap  ? "little" : "big";
        info["data_endian"]  = c->dataSwap ? "little" : "big";
        info["rx_channels"]  = std::to_string(_rx.size());
    }
    if (!_tx.empty()) {
        const TxChannel *c = _tx[0].get();
        info["tx_endpoint"] = c->destAddr + ":" + std::to_string(c->destPort);
        info["tx_format"]   = VRT::formatName(c->wireFormat);
        info["tx_channels"] = std::to_string(_tx.size());
    }
#ifdef HAVE_PCAP
    info["capture"] = "libpcap";
#else
    info["capture"] = "none";
#endif
    return info;
}

size_t SoapyVITA49::getNumChannels(const int direction) const
{
    return (direction == SOAPY_SDR_RX) ? _rx.size() : _tx.size();
}

bool SoapyVITA49::getFullDuplex(const int, const size_t) const
{
    /* Receive and transmit are independent UDP flows. */
    return !_rx.empty() && !_tx.empty();
}

/* ------------------------------------------------------------------ */
/* Antennas                                                           */
/* ------------------------------------------------------------------ */

std::vector<std::string> SoapyVITA49::listAntennas(const int direction,
                                                   const size_t) const
{
    return { direction == SOAPY_SDR_RX ? "RX" : "TX" };
}

void SoapyVITA49::setAntenna(const int, const size_t, const std::string &) {}

std::string SoapyVITA49::getAntenna(const int direction, const size_t) const
{
    return direction == SOAPY_SDR_RX ? "RX" : "TX";
}

/* ------------------------------------------------------------------ */
/* Control routing                                                    */
/* ------------------------------------------------------------------ */

/* Every parameter change goes through here. With a working control path the
 * value goes out as a command packet and is committed only on a clean ack;
 * otherwise it is recorded locally and a single warning explains why nothing
 * moved. */
bool SoapyVITA49::applyControl(int direction, size_t channel, uint32_t cif0Bit,
                               double value, const char *what)
{
    (void)direction;
    (void)channel;

    if (_control && _control->available()) {
        if (_control->setField(cif0Bit, value, _controlTimeoutMs))
            return true;
        SoapySDR::logf(SOAPY_SDR_WARNING, "vita49: %s command rejected: %s",
                       what, _control->lastError().c_str());
        return false;
    }

    if (!_controlWarned) {
        _controlWarned = true;
        SoapySDR::logf(SOAPY_SDR_WARNING,
            "vita49: the source does not answer VITA 49.2 commands, so %s and "
            "later parameter changes are recorded locally only - retune at the "
            "source", what);
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Frequency                                                          */
/* ------------------------------------------------------------------ */

std::vector<std::string> SoapyVITA49::listFrequencies(const int,
                                                      const size_t) const
{
    return { "RF" };
}

void SoapyVITA49::setFrequency(const int direction, const size_t channel,
                               const std::string &name, const double frequency,
                               const SoapySDR::Kwargs &)
{
    if (name != "RF" && !name.empty())
        return;

    /* A frequency the controllee refused is not recorded: the receiver did
     * not move, and the next context packet would say so anyway. */
    if (!applyControl(direction, channel, VRT::CIF0_RF_REF_FREQ, frequency,
                      "set frequency") && controlAvailable())
        return;

    std::lock_guard<std::mutex> lk(_mtx);
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        _rx[channel]->centerFreq = frequency;
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        _tx[channel]->centerFreq = frequency;
}

double SoapyVITA49::getFrequency(const int direction, const size_t channel,
                                 const std::string &name) const
{
    if (name != "RF" && !name.empty())
        return 0.0;
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        return _rx[channel]->centerFreq.load();
    if (direction == SOAPY_SDR_TX && channel < _tx.size())
        return _tx[channel]->centerFreq.load();
    return 0.0;
}

/*
 * A receiver that cannot command its source cannot retune, so the advertised
 * range collapses to the single frequency the context packets report. That is
 * the honest answer and it stops a host from silently believing a tune took
 * effect. Passing tune=free widens the range for hosts that want to move the
 * displayed centre frequency locally.
 */
SoapySDR::RangeList SoapyVITA49::getFrequencyRange(const int direction,
                                                   const size_t channel,
                                                   const std::string &name) const
{
    SoapySDR::RangeList list;
    if (name != "RF" && !name.empty())
        return list;

    if (_control && _control->available()) {
        list.push_back(SoapySDR::Range(0.0, 30.0e9));
        return list;
    }

    double f = getFrequency(direction, channel, "RF");
    if (f > 0.0)
        list.push_back(SoapySDR::Range(f, f));
    else
        list.push_back(SoapySDR::Range(0.0, 30.0e9));
    return list;
}

SoapySDR::ArgInfoList SoapyVITA49::getFrequencyArgsInfo(const int,
                                                        const size_t) const
{
    return SoapySDR::ArgInfoList();
}

/* ------------------------------------------------------------------ */
/* Sample rate and bandwidth                                          */
/* ------------------------------------------------------------------ */

void SoapyVITA49::setSampleRate(const int direction, const size_t channel,
                                const double rate)
{
    applyControl(direction, channel, VRT::CIF0_SAMPLE_RATE, rate,
                 "set sample rate");

    std::lock_guard<std::mutex> lk(_mtx);
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        _rx[channel]->sampleRate = rate;
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        _tx[channel]->sampleRate = rate;
}

double SoapyVITA49::getSampleRate(const int direction, const size_t channel) const
{
    if (direction == SOAPY_SDR_RX && channel < _rx.size()) {
        double r = _rx[channel]->sampleRate.load();
        /* Report something plausible before the first context packet so hosts
         * that divide by the rate do not trip over a zero. */
        return (r > 0.0) ? r : 1.0e6;
    }
    if (direction == SOAPY_SDR_TX && channel < _tx.size())
        return _tx[channel]->sampleRate.load();
    return 1.0e6;
}

std::vector<double> SoapyVITA49::listSampleRates(const int direction,
                                                 const size_t channel) const
{
    return { getSampleRate(direction, channel) };
}

SoapySDR::RangeList SoapyVITA49::getSampleRateRange(const int direction,
                                                    const size_t channel) const
{
    SoapySDR::RangeList list;
    if (_control && _control->available()) {
        list.push_back(SoapySDR::Range(1.0e3, 1.0e9));
    } else {
        double r = getSampleRate(direction, channel);
        list.push_back(SoapySDR::Range(r, r));
    }
    return list;
}

void SoapyVITA49::setBandwidth(const int direction, const size_t channel,
                               const double bw)
{
    applyControl(direction, channel, VRT::CIF0_BANDWIDTH, bw, "set bandwidth");

    std::lock_guard<std::mutex> lk(_mtx);
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        _rx[channel]->bandwidth = bw;
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        _tx[channel]->bandwidth = bw;
}

double SoapyVITA49::getBandwidth(const int direction, const size_t channel) const
{
    double bw = 0.0;
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        bw = _rx[channel]->bandwidth.load();
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        bw = _tx[channel]->bandwidth.load();
    /* Context packets often omit bandwidth; the sample rate is the best
     * available stand-in. */
    return (bw > 0.0) ? bw : getSampleRate(direction, channel);
}

SoapySDR::RangeList SoapyVITA49::getBandwidthRange(const int direction,
                                                   const size_t channel) const
{
    SoapySDR::RangeList list;
    double bw = getBandwidth(direction, channel);
    if (_control && _control->available())
        list.push_back(SoapySDR::Range(1.0e3, 1.0e9));
    else
        list.push_back(SoapySDR::Range(bw, bw));
    return list;
}

/* ------------------------------------------------------------------ */
/* Gain                                                               */
/* ------------------------------------------------------------------ */

/*
 * With a working control path the source can be commanded, so one overall
 * stage named GAIN is listed (hosts such as gqrx draw a slider only for named
 * stages) and the AGC/MGC indicator of the State/Event field serves as the
 * gain mode. Without control there is nothing to adjust and nothing is
 * listed. The range is the full 16-bit radix-7 span unless gain_range=
 * narrows it to what the source accepts.
 */
std::vector<std::string> SoapyVITA49::listGains(const int direction, const size_t) const
{
    if (direction == SOAPY_SDR_RX && controlAvailable())
        return { "GAIN" };
    return std::vector<std::string>();
}

bool SoapyVITA49::hasGainMode(const int direction, const size_t) const
{
    return direction == SOAPY_SDR_RX && controlAvailable();
}

void SoapyVITA49::setGainMode(const int direction, const size_t channel,
                              const bool automatic)
{
    if (direction != SOAPY_SDR_RX || channel >= _rx.size())
        return;
    if (!applyControl(direction, channel, VRT::CIF0_STATE_EVENT, automatic ? 1.0 : 0.0,
                      "set gain mode") && controlAvailable())
        return;
    _rx[channel]->agcMode = automatic ? 1 : 0;
}

bool SoapyVITA49::getGainMode(const int direction, const size_t channel) const
{
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        return _rx[channel]->agcMode.load() == 1;
    return false;
}

void SoapyVITA49::setGain(const int direction, const size_t channel,
                          const double value)
{
    if (!applyControl(direction, channel, VRT::CIF0_GAIN, value, "set gain") &&
        controlAvailable())
        return;

    std::lock_guard<std::mutex> lk(_mtx);
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        _rx[channel]->gain = value;
    else if (direction == SOAPY_SDR_TX && channel < _tx.size())
        _tx[channel]->gain = value;
}

double SoapyVITA49::getGain(const int direction, const size_t channel) const
{
    if (direction == SOAPY_SDR_RX && channel < _rx.size())
        return _rx[channel]->gain.load();
    if (direction == SOAPY_SDR_TX && channel < _tx.size())
        return _tx[channel]->gain.load();
    return 0.0;
}

SoapySDR::Range SoapyVITA49::getGainRange(const int direction,
                                          const size_t channel) const
{
    if (controlAvailable())
        return _haveGainRange ? _gainRange
                              : SoapySDR::Range(-256.0, 255.99);   /* full 16-bit radix-7 span */
    double g = getGain(direction, channel);
    return SoapySDR::Range(g, g);
}

/* The single named stage is the overall gain. */
void SoapyVITA49::setGain(const int direction, const size_t channel,
                          const std::string &name, const double value)
{
    if (name.empty() || name == "GAIN")
        setGain(direction, channel, value);
}

double SoapyVITA49::getGain(const int direction, const size_t channel,
                            const std::string &name) const
{
    return (name.empty() || name == "GAIN") ? getGain(direction, channel) : 0.0;
}

SoapySDR::Range SoapyVITA49::getGainRange(const int direction, const size_t channel,
                                          const std::string &name) const
{
    if (name.empty() || name == "GAIN")
        return getGainRange(direction, channel);
    return SoapySDR::Range(0.0, 0.0);
}

/* ------------------------------------------------------------------ */
/* Time                                                               */
/* ------------------------------------------------------------------ */

std::vector<std::string> SoapyVITA49::listTimeSources() const
{
    return { "vita49" };
}

std::string SoapyVITA49::getTimeSource() const { return "vita49"; }

bool SoapyVITA49::hasHardwareTime(const std::string &what) const
{
    return what.empty() || what == "vita49";
}

long long SoapyVITA49::getHardwareTime(const std::string &what) const
{
    if (!(what.empty() || what == "vita49"))
        return 0;
    if (_rx.empty())
        return 0;
    return _rx[0]->lastTimeNs.load();
}

/* ------------------------------------------------------------------ */
/* Settings                                                           */
/* ------------------------------------------------------------------ */

SoapySDR::ArgInfoList SoapyVITA49::getSettingInfo() const
{
    SoapySDR::ArgInfoList list;

    {
        SoapySDR::ArgInfo a;
        a.key         = "hdr_endian";
        a.name        = "Header byte order";
        a.description = "Byte order of VRT header words. The spec requires "
                        "big endian; some sources emit little endian.";
        a.type        = SoapySDR::ArgInfo::STRING;
        a.options     = { "big", "little" };
        a.value       = _rx.empty() ? "big" : (_rx[0]->hdrSwap ? "little" : "big");
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "data_endian";
        a.name        = "Sample byte order";
        a.description = "Byte order of payload samples, which some sources set "
                        "independently of the header order.";
        a.type        = SoapySDR::ArgInfo::STRING;
        a.options     = { "big", "little" };
        a.value       = _rx.empty() ? "big" : (_rx[0]->dataSwap ? "little" : "big");
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "iq_swap";
        a.name        = "Exchange I and Q";
        a.description = "Undo the sample order of a source that sends Q first, "
                        "which otherwise mirrors the spectrum.";
        a.type        = SoapySDR::ArgInfo::BOOL;
        a.value       = (!_rx.empty() && _rx[0]->iqSwap) ? "true" : "false";
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "wire_format";
        a.name        = "Wire sample format";
        a.description = "Override the payload format instead of taking it from "
                        "context packets.";
        a.type        = SoapySDR::ArgInfo::STRING;
        a.options     = { "auto", "ci8", "ci12", "ci16", "cf32" };
        a.value       = _rx.empty() ? "auto" : VRT::formatName(_rx[0]->wireFormat);
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "ctrl_cam";
        a.name        = "CAM override";
        a.description = "Raw hexadecimal Control/Acknowledge Mode word, for a "
                        "controllee whose profile differs from VITA 49.2.";
        a.type        = SoapySDR::ArgInfo::STRING;
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "time_source";
        a.name        = "Timestamp source";
        a.description = "stream uses the source's timestamps, host stamps on "
                        "arrival, auto corrects the source's epoch from the "
                        "first packet while keeping its precision.";
        a.type        = SoapySDR::ArgInfo::STRING;
        a.options     = { "stream", "auto", "host" };
        a.value       = _timeUseHost ? "host" : (_timeAuto ? "auto" : "stream");
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "time_offset";
        a.name        = "Timestamp correction";
        a.description = "Seconds added to every timestamp.";
        a.type        = SoapySDR::ArgInfo::FLOAT;
        a.value       = std::to_string(_timeOffsetNs.load() / 1e9);
        list.push_back(a);
    }
    {
        SoapySDR::ArgInfo a;
        a.key         = "stats";
        a.name        = "Stream statistics";
        a.description = "Read-only packet, gap and drop counters.";
        a.type        = SoapySDR::ArgInfo::STRING;
        list.push_back(a);
    }

    return list;
}

void SoapyVITA49::writeSetting(const std::string &key, const std::string &value)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (key == "hdr_endian") {
        bool sw = parseEndian(value, false);
        for (auto &c : _rx) c->hdrSwap = sw;
        for (auto &c : _tx) c->hdrSwap = sw;
    } else if (key == "data_endian") {
        bool sw = parseEndian(value, false);
        for (auto &c : _rx) c->dataSwap = sw;
        for (auto &c : _tx) c->dataSwap = sw;
    } else if (key == "iq_swap") {
        bool on = !(value == "0" || value == "false" || value == "no");
        for (auto &c : _rx) c->iqSwap = on;
        for (auto &c : _tx) c->iqSwap = on;
    } else if (key == "wire_format") {
        VRT::SampleFormat f = parseWireFormat(value);
        bool locked = (f != VRT::FMT_UNKNOWN);
        for (auto &c : _rx) {
            c->wireFormatLocked = locked;
            if (locked) c->wireFormat = f;
        }
        for (auto &c : _tx)
            if (locked) c->wireFormat = f;
    } else if (key == "ctrl_cam") {
        if (_control)
            _control->setCamOverride(!value.empty(),
                (uint32_t)strtoul(value.c_str(), nullptr, 0));
    } else if (key == "ctrl_probe") {
        if (_control) {
            VRT::ContextInfo cur;
            bool ok = _control->probe(atoi(value.c_str()) ? atoi(value.c_str()) : 500,
                                      &cur);
            SoapySDR::logf(SOAPY_SDR_INFO, "vita49: control probe %s",
                           ok ? "succeeded" : "timed out");
        }
    }
}

std::string SoapyVITA49::readSetting(const std::string &key) const
{
    if (key == "hdr_endian")
        return _rx.empty() ? "big" : (_rx[0]->hdrSwap ? "little" : "big");
    if (key == "data_endian")
        return _rx.empty() ? "big" : (_rx[0]->dataSwap ? "little" : "big");
    if (key == "wire_format")
        return _rx.empty() ? "auto" : VRT::formatName(_rx[0]->wireFormat);
    if (key == "iq_swap")
        return (!_rx.empty() && _rx[0]->iqSwap) ? "true" : "false";
    if (key == "control")
        return (_control && _control->available()) ? "vita49.2" : "none";
    if (key == "time_source")
        return _timeUseHost ? "host" : (_timeAuto ? "auto" : "stream");
    if (key == "time_offset")
        return std::to_string(_timeOffsetNs.load() / 1e9);

    if (key == "stats") {
        std::string s;
        for (size_t i = 0; i < _rx.size(); i++) {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "rx%zu packets=%llu gaps=%llu dropped=%llu overrange=%llu; ",
                     i,
                     (unsigned long long)_rx[i]->packets.load(),
                     (unsigned long long)_rx[i]->gaps.load(),
                     (unsigned long long)(_rx[i]->queue ? _rx[i]->queue->dropped() : 0),
                     (unsigned long long)_rx[i]->overRange.load());
            s += buf;
        }
        for (size_t i = 0; i < _tx.size(); i++) {
            char buf[160];
            snprintf(buf, sizeof(buf), "tx%zu packets=%llu underflows=%llu; ",
                     i,
                     (unsigned long long)_tx[i]->packets.load(),
                     (unsigned long long)_tx[i]->underflows.load());
            s += buf;
        }
        if (_control) {
            char buf[128];
            snprintf(buf, sizeof(buf), "control sent=%llu acks=%llu",
                     (unsigned long long)_control->commandsSent(),
                     (unsigned long long)_control->acksReceived());
            s += buf;
        }
        return s;
    }

    return "";
}
