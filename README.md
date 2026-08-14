# SoapyVITA49

A SoapySDR driver for VITA 49 (VRT) streams carried over UDP, with receive,
transmit and optional VITA 49.2 control.

Once installed, network streams appear in the device lists of GQRX, CubicSDR,
SDRangel, GNU Radio and `SoapySDRUtil` alongside locally attached radios, and
open the same way. Sample rate, centre frequency, bandwidth and payload format
are taken from the stream's own context packets, so nothing has to be
configured by hand.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Discovery](#discovery)
- [What is read from a stream](#what-is-read-from-a-stream)
- [How devices are identified](#how-devices-are-identified)
- [Multiple streams](#multiple-streams)
- [Concurrent applications](#concurrent-applications)
- [Transmitting](#transmitting)
- [Control](#control)
- [Timestamps](#timestamps)
- [Wire dialects](#wire-dialects)
- [Device arguments](#device-arguments)
- [Tools](#tools)
- [Throughput](#throughput)
- [Status](#status)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Background

This driver implements ANSI/VITA 49.0-2015, the VITA Radio Transport standard,
and the command packet classes added by ANSI/VITA 49.2-2017. Section numbers in
the source and in this document refer to those two, 49.0 unless 49.2 is named.
Both are published by the VITA Standards Organization and are not freely
redistributable, so they are cited rather than reproduced.

VITA 49, also called VRT, carries digitised IF or RF samples over a network.
A source emits signal data packets holding the samples and context packets
describing them, and a receiver reassembles a stream from both.

The protocol has no discovery mechanism. A source sends to an address and port
and announces itself to nobody, so a receiver must either be told where to
listen or go looking. Much of the work in this driver is in bridging that gap:
finding streams, deciding which of them are real, and presenting each as a
device that existing software already knows how to open.

VITA 49.0 is one-way. It describes a stream but offers no way to change it.
VITA 49.2 adds command packets, which this driver uses when the source answers
them and does without when it does not.

## Install

Requires SoapySDR 0.8 and a C++11 compiler. libpcap is optional; without it,
discovery falls back to binding ports.

```sh
sudo apt install libsoapysdr-dev libpcap-dev cmake g++
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
sudo cmake --install build
```

Confirm the module loaded, and run the packet-layer tests:

```sh
SoapySDRUtil --info | grep vita49
./build/test-vrt
```

Discovery by packet capture needs `CAP_NET_RAW`. Granting it to the tools is
enough; the driver itself falls back to binding ports.

```sh
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v vita49-scan)"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v vita49-dump)"
```

## Usage

Nothing has to be scanned or configured first. Open a graphical application and
any stream reaching this machine appears in its device list, ready to select.

The driver finds streams itself. It reads its cache when one exists, and sweeps
for streams when it does not, so the first enumeration on a new machine takes a
second or two and every one after that is instant. Running `vita49-scan` by
hand is optional and only ever an optimisation or a diagnostic.

From the command line:

```sh
SoapySDRUtil --find="driver=vita49"
SoapySDRUtil --probe="driver=vita49,addr=0.0.0.0,port=4991,sid=0x1"
```

A device string can also be entered directly, which skips discovery entirely
and is the right choice in a script or a fixed installation:

```
driver=vita49,addr=0.0.0.0,port=4991,sid=0x1
```

From Python:

```python
import SoapySDR, numpy as np
from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_CF32

sdr = SoapySDR.Device(dict(driver="vita49", addr="0.0.0.0",
                           port="4991", sid="0x1"))
stream = sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32)
sdr.activateStream(stream)

buf = np.zeros(8192, np.complex64)
status = sdr.readStream(stream, [buf], len(buf))
```

Sample rate and frequency need not be set. They arrive in context packets, and
`getSampleRate()` and `getFrequency()` report what the source sent.

## Discovery

Discovery is automatic. Nothing below has to be run by hand; this section
explains what happens when an application asks for a device list, and how to
influence it.

Enumeration is called whenever a host refreshes its device list, so it has to
stay quick. Three tiers are tried in order.

**A named address and port** needs no discovery. This is the only method that
works before a source has started, and the one to use in scripts and fixed
installations.

**The cache**, at `~/.cache/SoapyVITA49/streams.conf`, is read instantly.
Entries are re-checked against the network before being offered, because the
cache records what was true when it was written:

```
VITA-49 0.0.0.0:4991 sid 00000001 2400.000 MHz 61.44 Msps
VITA-49 0.0.0.0:4992 sid 00000002 2400.000 MHz 61.44 Msps [in use by another app]
VITA-49 0.0.0.0:4999 sid 000000ff 1575.420 MHz 122.9 Msps [not streaming]
```

A stopped stream is labelled rather than removed, since a source that has not
been started yet is still worth offering; `hide_idle=1` drops those instead. A
port another process holds is reported as in use rather than dead, which is the
more useful answer when a device will not open. The check costs a few hundred
milliseconds and touches only cached endpoints.

**A scan**, when the cache is empty or one is asked for. This happens by itself
on a machine that has never seen a stream: the whole unprivileged port range is
swept, which takes a little over a second, and the result is cached so the next
enumeration is immediate.

Running `vita49-scan` by hand is worth it for two reasons. It moves that
one-off cost out of the application, and it can scan by capture, which sees
streams a bind scan cannot.

Two scan mechanisms see different things:

| | Capture scan | Bind scan |
| --- | --- | --- |
| Privileges | `CAP_NET_RAW` | none |
| Ports another process holds | visible | invisible |
| Multicast not joined | visible | invisible |
| Port range needed | no | yes |

The bind scan raises its own descriptor limit so the whole range can be held
open at once and listened to in a single pass, rather than swept in windows
short enough to miss a stream.

Blind scanning invites false positives, so a datagram is accepted as VITA 49
only when it decodes structurally *and* either a context packet parsed cleanly
or at least three consecutive data packets stepped the packet counter by one.
Unrelated protocols do not do that.

## What is read from a stream

Context packets describe the stream, and a source may send any subset of the
fields in any packet. These are decoded and reported:

| Field | Reported as |
| --- | --- |
| Sample rate | `getSampleRate()` |
| RF reference frequency | `getFrequency()` |
| Bandwidth | `getBandwidth()` |
| Gain, both stages | `getGain()`, summed |
| Reference level | `refLevel` in device information |
| Temperature | device information |
| Over-range count | `stats` setting |
| Data payload format | selects the decoder; `format=` overrides |
| Device identifier | device information, manufacturer OUI and device code |

Signal data packets may also carry a trailer, which reports what the source
thinks of its own data: calibrated time, valid data, reference lock, AGC,
detected signal, spectral inversion, over-range and sample loss. Over-range and
sample loss are counted and raised to the application as stream flags. The
source's own sample-loss indicator is worth more than the packet counter, since
it catches samples lost before they were ever sent.

Each field carries a separate present flag, because a source that does not
report over-range is saying something different from one reporting no
over-range.

## How devices are identified

Every enumerated stream carries a `serial` built from its endpoint and stream
identifier, such as `0.0.0.0:4991/00000001`. It is unique per stream and stable
across enumerations, so an application that remembers a device selection
between sessions resolves the same stream again.

This matters because applications differ in what they key on. Some identify a
device by its label, others by serial alone; a driver that omits the serial has
every stream collapse into a single entry in the latter.

A source may also identify itself, in the Class ID of the packet header or the
Device Identifier field of a context packet, both carrying a manufacturer OUI.
Neither is required and many sources send neither, so both are reported for
diagnosis rather than relied upon.

## Multiple streams

A source may carry several streams, either on separate ports or multiplexed
onto one port and separated by stream identifier. Both are handled, and there
are two ways to present them.

**One device per stream** is the default. Each becomes its own entry, which is
what allows an application with no channel selector to pick one:

```
$ SoapySDRUtil --find="driver=vita49"
Found device 0
  label = VITA-49 0.0.0.0:4992 sid 00000022 2412.000 MHz 8 Msps
Found device 1
  label = VITA-49 0.0.0.0:4991 sid 00000011 1575.420 MHz 2 Msps
Found device 2
  label = VITA-49 0.0.0.0:4991 sid 00000033 462.562 MHz 1 Msps
```

Devices 1 and 2 share a port and are separated by stream identifier. They open
independently; the driver binds the port once and demultiplexes.

**One multi-channel device** suits GNU Radio. Pass `sid=all` and every stream
on the port becomes a channel:

```sh
SoapySDRUtil --probe="driver=vita49,addr=0.0.0.0,port=4991,sid=all"
```

`readStream()` must return the same element count for every channel, so
combining streams of unequal sample rate throttles the faster ones to the
slowest and discards the difference. The driver warns when it sees this.
Streams of differing rates are better opened as separate devices.

## Concurrent applications

Each application loads its own copy of the driver into its own process. There
is no shared daemon, and no coordination beyond what the kernel enforces on UDP
ports, so the outcome depends on how the source sends.

**Different streams on different ports** run independently at full rate.
Closing one frees its port and affects nothing else.

**One unicast stream, several applications** cannot work, because a unicast
datagram is delivered to exactly one socket. The second application is refused
with an explanation rather than allowed to start. Setting `SO_REUSEADDR` would
let it bind, but the kernel would then hand it most of the traffic and leave
the first application with a fraction of the stream, no error and no sequence
gaps to reveal it. A silent failure that resembles weak signal is worse than a
refusal. Pass `reuse=1` to override this.

**One multicast group, several applications** works. Every receiver that joins
gets its own copy, and closing one does not disturb the rest: group membership
is counted per socket and the group is left only when the last socket goes.

## Transmitting

Transmit has not been proven against another implementation; see
[Status](#status) before relying on it.

Transmit needs an explicit destination, since a receiver that is not yet
running emits nothing to discover.

```python
tx = SoapySDR.Device(dict(driver="vita49", rx="0",
                          tx_addr="192.168.1.50", tx_port="4991",
                          tx_sid="0x1", tx_rate="1000000",
                          tx_freq="915000000", tx_format="ci16"))
```

Packets are sized to the MTU, timestamped, and paced against an absolute
schedule derived from the sample rate. A UDP receiver has no flow control, so a
sender that transmits as fast as it can will overrun it. A context packet
describing rate, frequency and format is emitted once a second by default,
which is what allows a receiver to configure itself without being told anything
out of band.

`writeStream()` blocks while the pacer works through the queue, giving ordinary
backpressure. Falling behind is counted and reported through
`readStreamStatus()` as an underflow.

## Control

At open, the driver sends a query-state command and waits for an
acknowledgement. If one arrives, `setFrequency()` and its siblings are sent as
command packets and committed only on a clean acknowledgement. If nothing
answers, which is what a VITA 49.0 source does, the driver reports this once
and runs receive-only:

```
[INFO] vita49: no VITA 49.2 acknowledgement from 192.168.1.50:4991, running receive-only
```

In that state, parameter changes are recorded locally so the host sees a
consistent device, and the advertised frequency, rate and gain ranges collapse
to the single value the source reports. This is deliberate: a range that claims
to be adjustable when nothing can be adjusted invites a host to believe a tune
succeeded.

`control=on` makes a missing control path an error rather than a fallback, and
`control=off` skips the probe. A controllee whose profile differs from the
specification can be accommodated by replacing the Control and Acknowledge Mode
word with `ctrl_cam=0x...`.

## Timestamps

Signal data packets carry a timestamp, reported as `timeNs` from
`readStream()` and by `getHardwareTime()`. Whether it means anything depends on
the source. The timestamp is absolute, but nothing obliges a source to say
whether its clock was ever set, and the CIF0 fields that would describe this,
Timestamp Adjustment and Timestamp Calibration Time, are routinely omitted. An
undisciplined source is therefore silently wrong. `vita49-dump` reports the
difference against the host clock on every timestamped packet.

`time_source` selects what to do about it:

| Value | Behaviour |
| --- | --- |
| `stream` | Use the timestamps as sent. The default, and correct for a disciplined source. |
| `auto` | Measure the offset from the first timestamped packet and apply it thereafter, keeping the source's precision and correcting only its epoch. |
| `host` | Ignore the source's timestamps and stamp packets on arrival. |

`time_offset` adds a fixed number of seconds on top.

Relative timing within a stream, and between streams from one source, is
unaffected by a wrong epoch, since they share a clock and a common offset
cancels. That is enough to sample-align several channels from one receiver.

Absolute timing is a different matter. `auto` and `host` are only as good as
this machine's clock, which under NTP is milliseconds. That suffices for
logging, for recorded IQ that must line up with an external log, and for
scheduled capture. It is nowhere near enough for TDOA or FDOA geolocation,
which need separated receivers to agree to well under a microsecond, and for
which there is no substitute for disciplining the source itself.

## Wire dialects

The specification requires big-endian. Sources do not always comply, and they
set header and sample byte order independently. Header order is detected from
the packet structure; sample order follows it unless set explicitly:

```
driver=vita49,addr=...,hdr_endian=little,data_endian=big
```

Sample byte order cannot be read from the packet, so it is inherited from the
header order and may be wrong. It is measurable, though: a band-limited signal
correlates from one sample to the next, while the same bytes read the wrong way
correlate at nothing. The first payload of each stream is checked both ways and
a decisive mismatch is reported:

```
samples look byte-swapped (correlation -0.00 as read, 0.71 reversed); try data_endian=little
```

Nothing is changed automatically. A wrong guess would corrupt every sample
silently, whereas a wrong warning costs one line, so the check reports and
leaves the decision to the operator.

Some sources place Q ahead of I, which mirrors the spectrum. That cannot be
detected, because without knowing the signal either order is plausible, so
`iq_swap=1` corrects it and `tx_iq_swap` does the same on transmit.

Payload formats supported are `ci8`, `ci12` (link-efficient packed), `ci16` and
`cf32`. The format normally comes from the Data Packet Payload Format field of
a context packet; `format=` overrides it, which is what is wanted when a source
misdeclares its own payload. VRL framing is detected and stripped
automatically.

Arguments given explicitly always take precedence over what discovery detected,
so an override such as `data_endian=` applies even when probing disagrees.

A source may identify itself in two optional places: the Class ID in the packet
header, and the Device Identifier field of a context packet, both carrying a
manufacturer OUI. Neither is required and many sources send neither, so they
are reported by `vita49-dump` and in the device information rather than relied
upon.

## Device arguments

| Key | Default | Meaning |
| --- | --- | --- |
| `addr` | `0.0.0.0` | Address to bind, or a multicast group to join |
| `port` | `4991` | UDP port |
| `sid` | `any` | Stream identifier, `all` for multi-channel, or `any` |
| `format` | from context | Force the payload format |
| `hdr_endian` | detected | `big` or `little` |
| `data_endian` | follows header | `big` or `little` |
| `iq_swap` | `0` | Exchange I and Q for sources that send Q first |
| `tx_iq_swap` | follows `iq_swap` | The same on transmit |
| `rate`, `freq`, `bandwidth` | from context | Values to use until context arrives |
| `scan` | `cache` | `cache`, `quick`, `full` or `off` |
| `dwell` | 1500 ms | Listening window when probing or scanning |
| `probe` | `1` | Listen before offering a named endpoint |
| `verify` | `1` | Re-check cached entries against the network |
| `verify_ms` | 400 | Dwell for that re-check |
| `hide_idle` | `0` | Omit cached streams that are no longer running |
| `reuse` | `0` | Permit a second receiver on one unicast port |
| `buffers` | 512 | Queued packets per channel before the oldest is dropped |
| `rcvbuf` | 16 MiB | Socket receive buffer requested |
| `time_source` | `stream` | `stream`, `auto` or `host` |
| `time_offset` | 0 | Seconds added to every timestamp |
| `control` | `auto` | `auto`, `on` or `off` |
| `ctrl_addr`, `ctrl_port` | source address, data port | Where commands are sent |
| `ctrl_timeout` | 500 ms | Acknowledgement wait |
| `ctrl_cam` | computed | Raw Control and Acknowledge Mode word |
| `ctrl_dry_run` | `0` | Ask the controllee to validate commands without applying them |
| `ctrl_ack` | `1` | Wait for an acknowledgement before committing a change |
| `tx_addr`, `tx_port` | — | Transmit destination; required for transmit |
| `tx_sid` | `0x1` | Transmit stream identifier |
| `tx_rate`, `tx_freq` | — | Rate to pace at, and frequency to advertise |
| `tx_format` | `ci16` | Transmit payload format |
| `mtu` | 1472 | UDP payload budget per packet |
| `tx_context` | `1` | Emit periodic context packets |
| `context_rate` | 1.0 | Context packets per second |

## Tools

`vita49-scan` finds streams and writes the cache.

```sh
vita49-scan                      # capture scan if permitted, bind scan otherwise
vita49-scan -w                   # well-known ports only
vita49-scan -p 40000-50000       # a specific range
vita49-scan -e 239.1.2.3:4991    # one endpoint
vita49-scan -f capture.pcap      # replay a capture file
vita49-scan -c                   # print the cache
```

`vita49-dump` decodes packets field by field. This is the tool for an
unfamiliar source: it reports which stream identifiers are present, whether
context packets are sent at all, what payload format is declared, which byte
order is in use, and how far the source's clock differs from this host's.

```sh
vita49-dump -e 0.0.0.0:4991 -T 5     # listen five seconds
vita49-dump -f capture.pcap -d 1000  # replay, plus every 1000th data packet
vita49-dump -e 0.0.0.0:4991 -T 5 -x  # with hex dumps
```

Prefer `-T` over `-n`. Context packets are typically sent about once a second,
so a run bounded by packet count can stop after a few milliseconds of data and
wrongly suggest there are none.

`vita49-bench` streams and discards, so that only the network, the kernel and
this driver are exercised. It separates the two ways samples are lost.

```sh
vita49-bench -p 4991,4992,4993 -F CS16 -t 8
```

`vita49-gen` emits a synthetic stream for testing a receiver without hardware.

```sh
vita49-gen -d 127.0.0.1 -p 4991 -s 0x1 -r 2000000 -f 1575420000 -F ci16
vita49-gen -p 4992 -F ci12 -L        # 12-bit packed, little-endian
```

## Throughput

At high rates the host, not this driver, is the limit. Three things matter, in
order.

**Socket receive buffer.** The distribution default is around 200 kB, which at
10 GbE is under a millisecond of slack; any scheduling delay becomes lost
packets. The driver warns when its request is clamped. Size it for the stall
you want to survive, roughly bytes per second times seconds:

```sh
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.netdev_max_backlog=250000
```

Add these to `/etc/sysctl.d/` to make them persist, then pass a matching
`rcvbuf=` to the device.

**Interface ring buffers and MTU.** Defaults are usually well below what the
hardware supports. Jumbo frames matter twice over: they cut the datagram rate,
and a packet that fits in one frame never fragments.

```sh
sudo ethtool -G eth0 rx 4096
sudo ip link set eth0 mtu 9000
```

**How streams are distributed.** One receiver thread runs per bound endpoint,
meaning per address and port. Streams on separate ports get separate threads
and scale across cores; streams multiplexed onto one port share a socket and
therefore one thread for the aggregate rate. Where a source can be configured
either way, separate ports are better at high rates.

Two counters distinguish the two failure modes, and they have different
remedies:

- `gaps` counts breaks in the packet counter, meaning datagrams were lost
  before the driver saw them. Raise `rmem_max` and the interface ring.
- `dropped` counts blocks the driver discarded because the application did not
  read fast enough. Read larger chunks, use `CS16`, or do less per sample.

Both are reported by `vita49-bench` and by the `stats` device setting.

## Status

Receive is the exercised path. It has been run continuously at high rates
against live sources and against the bundled generator in every supported
payload format and byte order, including multiple streams sharing one port and
several applications running at once.

**Transmit has not been used in service, and nothing other than this driver has
ever received its output.** It builds packets, paces them against the sample
rate and emits context packets, and this driver's own receiver decodes them
correctly, sample values and timestamps intact. But both ends were written
together and share the same reading of the standard, so a mistake common to
both would pass unnoticed. Until another implementation has received a stream
from it, treat transmit as unproven.

The VITA 49.2 control path is in the same position, and more so: it has never
been answered by a controllee at all, because nothing tested against it
implements command packets. The bit layouts follow the standard and are
consistent with published implementations, but consistency is not the same as
having worked.

## Limitations

- The VITA 49.2 control path is implemented to the specification but has not
  been exercised against a controllee that implements it.
- Multi-channel streams of unequal sample rate run at the slowest rate.
- `ci12` is supported only in specification byte order, since the packing is
  defined over the big-endian word stream and has no byte-swapped variant.
- The capture scan does not reassemble IP fragments. Later fragments are
  discarded outright, and a first fragment fails the length check because its
  declared packet size exceeds what was captured. A source whose packets
  fragment needs an explicit address and port rather than discovery.
- Received datagrams larger than 16 kB are dropped with an error rather than
  silently truncated. This is well above a jumbo frame but below the 64 kB a
  UDP datagram may reach.
- IPv6 is classified during a capture scan, but streams are received over IPv4.
- Only complex cartesian payloads are usable. Real and complex-polar streams
  are valid VRT but have no SoapySDR equivalent.
- A stream that moves to a different port is not noticed by the cache check,
  which listens only to endpoints already known. Re-run `vita49-scan` after
  reconfiguring a source.

## Contributing

Issues and pull requests are welcome. Changes to the packet layer should come
with a case in `tests/test_vrt.cpp`; that suite runs without hardware and is
the fastest way to demonstrate a decoding problem. When reporting a source that
does not decode correctly, the output of `vita49-dump -e ADDR:PORT -T 5` says
more than a description, and `-x` adds the bytes.

## License

GPL-3.0-or-later. Copyright (c) 2026 CEMAXECUTER LLC.
