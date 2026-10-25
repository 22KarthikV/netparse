# netparse

A zero-copy Ethernet / 802.1Q / IPv4 / IPv6 / TCP / UDP packet parser in C11,
with a hand-written pcap reader, a fixed-size TCP flow tracker, a capture and
inspection CLI, and a test suite that checks the output against scapy and
tshark.

```
make && make test
./build/netparse -r examples/sample.pcap
```

## Why

Kernel-bypass stacks such as Onload hand an application raw frames straight
from the NIC ring. At 10 GbE line rate with minimum-size frames that is one
frame every 67 ns, so any per-packet work done in that path has to be
cheap and predictable: no allocation, no copying, no branches on data that
has not been bounds checked. netparse is written to those rules, and it
measures what that costs on one core.

The flow tracker answers the question that matters when a trading
connection sees a latency spike: was it a retransmission, reordering, a
zero window, or loss upstream of the capture point. Its classifications are
checked packet by packet against Wireshark's TCP analysis.

## Layout

```
include/netparse/   public headers: netparse.h (parser), pcap.h, flow.h
src/                library: parse.c, pcap.c, flow.c, load.h (byte-order loads)
tools/netparse.c    CLI: pcap reader and AF_PACKET TPACKET_V3 live capture
tests/unit_tests.c  C unit tests (self-contained runner in tests/test.h)
tests/py/           pytest harness (scapy and tshark as references)
fuzz/               libFuzzer / AFL++ harnesses, seed corpus, campaign script
bench/              single-core throughput benchmark
examples/           sample.pcap and the script that generates it
```

## Design

### Parser (`np_parse_eth`, `np_parse_ip`)

The caller passes a buffer and its captured length. The parser fills an
`np_packet` with decoded header fields in host byte order and with 16-bit
offsets into the caller's buffer (`l3_off`, `l4_off`, `payload_off`). It
never allocates and never copies packet bytes. The struct is reset field by
field rather than with `memset`, so only the fields for layers that were
present are written.

- **Bounds checking.** Each layer receives the offset of its header and
  computes `avail = caplen - off`. A field is read only after a check that
  proves it lies inside the capture. Lengths come from 16-bit header fields
  and are combined in `size_t`, so the arithmetic cannot wrap.
- **No unaligned-access UB.** All multi-byte reads go through
  `np_be16`/`np_be32` in `src/load.h`, which `memcpy` into a local and
  byte-swap. gcc and clang compile these to a single load plus `bswap`/`movbe`.
- **Errors.** Each malformed or truncated header has its own error code
  (`NP_ERR_TRUNC_TCP`, `NP_ERR_TCP_OPTIONS`, `NP_ERR_IPV4_FRAG`, ...). On error
  the layers already decoded remain valid; `pkt.layers` says which.
- **Captured vs. declared length.** If the IP total length exceeds the
  capture (snaplen), headers are still decoded as long as they fit, the
  packet is flagged `NP_F_TRUNCATED`, and `payload_caplen < payload_len`.
  Bytes after the datagram (Ethernet padding) are flagged and ignored.
- **Checksums are flags, not errors.** IPv4 header and TCP/UDP checksums are
  verified only on request (`NP_OPT_IP_CSUM`, `NP_OPT_L4_CSUM`) and reported
  as `NP_F_IP_CSUM_BAD` / `NP_F_L4_CSUM_BAD`, because captures taken on a host
  with checksum offload routinely contain bad TCP checksums.

What is decoded:

| Layer | Fields and checks |
|-------|-------------------|
| Ethernet II | ethertype; 802.3 length frames are recognised and stop at L2 |
| VLAN | up to 2 tags (802.1Q, or 802.1ad/0x9100 + 802.1Q); TPID, PCP, DEI, VID; a third tag is `NP_ERR_VLAN_DEPTH` |
| IPv4 | version, IHL >= 5, total length >= header, option TLV walk (EOL, NOP, length >= 2 and in bounds), DF/MF, fragment offset, offset + length <= 65535, optional checksum |
| IPv6 | version, payload length, traffic class, flow label; walks up to 8 hop-by-hop / routing / fragment / destination-options headers |
| Fragments | the first fragment's L4 header is parsed; later fragments stop at L3 (`NP_F_IP_FRAG_LATER`); no reassembly |
| TCP | ports, seq, ack, data offset (>= 5, within the datagram), flags, window, urgent pointer; options MSS, window scale, SACK-permitted, SACK (1-4 blocks), timestamps; each known option's length is checked, unknown options are skipped by length |
| UDP | ports, length (>= 8, <= IP payload except on first fragments), checksum (0 = absent on IPv4) |

### pcap reader

`np_pcap_open_mem` / `np_pcap_next` read the classic libpcap format
(little- and big-endian, microsecond and nanosecond magic) from memory.
Records are returned as pointers into the buffer. `np_pcap_map_file` mmaps
a regular file, or reads a pipe into memory. Truncated record headers,
truncated data and `incl_len` above 256 KiB are errors; the reader stops at
the first one. pcapng is not supported.

### Flow tracker

`np_flow_table` is an open-addressing hash table over storage the caller
provides (power-of-two slot count, linear probing, inserts refused at 7/8
occupancy and counted in `dropped`). The key is the canonical 5-tuple, so
both directions of a connection share one slot; each direction keeps its
own counters and sequence state. There is no per-packet allocation.

Per-direction TCP analysis, with the same definitions Wireshark uses where
they overlap:

| Event | Definition |
|-------|-----------|
| gap | segment starts after the highest sequence seen; the missing range is recorded as a hole (Wireshark: "previous segment not captured") |
| out-of-order | segment lies wholly inside a recorded hole and arrives within 3 ms of the packet that opened it |
| retransmission | segment covers sequence space already seen, or fills a hole later than 3 ms (data lost before the capture point) |
| keep-alive | 0 or 1 byte at highest sequence - 1, no SYN/FIN/RST |
| duplicate ACK | no payload, no SYN/FIN/RST, non-zero window, same ack and window as the previous packet in that direction, not the answer to a keep-alive |
| zero window | window 0 on a packet without SYN/FIN/RST |
| SACK | packet carries a SACK option; blocks are counted too |

Holes are kept in a fixed array of 8 per direction and dropped when the
other side acknowledges past them. Sequence comparisons use RFC 1982 serial
arithmetic, so they work across the 2^32 wrap. MSS and window scale are
recorded from each side's SYN.

### CLI

```
netparse [-jqFn] [-c count] -r file.pcap
netparse [-jqFn] [-c count] -i iface     # Linux, needs CAP_NET_RAW
  -j JSON lines   -q no per-packet lines   -F no flow table
  -n skip checksum verification            -c stop after N packets
```

Live capture uses an `AF_PACKET` socket with a memory-mapped `TPACKET_V3`
receive ring (16 x 1 MiB blocks). Frames are parsed in place in the ring and
each block is handed back to the kernel once processed. On loopback the
outgoing copy of each frame is dropped, as libpcap does.

### Example output

`examples/sample.pcap` is generated by `examples/make_sample.py`: a TCP
connection with a segment lost before the capture point, duplicate ACKs
with SACK, a fast retransmit and a zero window, then a VLAN-tagged UDP
stream and a fragmented UDP datagram. Output of
`./build/netparse -r examples/sample.pcap` (trimmed):

```
1700000000.000100 IP 10.0.0.1.40000 > 10.0.0.2.8080: Flags [S], seq 1000, win 8192, options [mss 1460,wscale 7,sackOK,TS val 100 ecr 0], length 0
1700000000.000500 IP 10.0.0.1.40000 > 10.0.0.2.8080: Flags [.], seq 1001:2001, ack 9001, win 8192, length 1000
1700000000.000550 IP 10.0.0.2.8080 > 10.0.0.1.40000: Flags [.], seq 9001, ack 2001, win 8192, length 0
1700000000.000600 IP 10.0.0.2.8080 > 10.0.0.1.40000: Flags [.], seq 9001, ack 2001, win 8192, length 0 [dup-ack]
1700000000.000700 IP 10.0.0.1.40000 > 10.0.0.2.8080: Flags [.], seq 3001:4001, ack 9001, win 8192, length 1000 [gap]
1700000000.000750 IP 10.0.0.2.8080 > 10.0.0.1.40000: Flags [.], seq 9001, ack 2001, win 8192, options [sack 1 {3001:4001}], length 0 [dup-ack] [sack]
1700000000.021050 IP 10.0.0.1.40000 > 10.0.0.2.8080: Flags [.], seq 2001:3001, ack 9001, win 8192, length 1000 [retransmission]
1700000000.021250 IP 10.0.0.2.8080 > 10.0.0.1.40000: Flags [.], seq 9001, ack 6001, win 0, length 0 [zero-window]
1700000000.321649 vlan 200 p 4 IP 10.0.1.5.30001 > 239.1.1.1.30001: UDP, length 56
1700000000.321949 IP 10.0.0.1.5000 > 10.0.0.2.5001: UDP, length 1392 (frag id 4242 off 0 MF)
1700000000.322049 IP 10.0.0.1 > 10.0.0.2: frag off 1400 UDP, length 608 (frag id 4242 off 1400)

Flows: 3
  udp 10.0.1.5:30001 <-> 239.1.1.1:30001
      pkts 3/0  bytes 252/0  payload 168/0
  udp 10.0.0.1:5000 <-> 10.0.0.2:5001
      pkts 1/0  bytes 1420/0  payload 1392/0
  tcp 10.0.0.1:40000 <-> 10.0.0.2:8080
      pkts 9/10  bytes 5380/456  payload 5000/0
      retrans 1/0  ooo 0/0  dupack 0/4  sack 0/3 (blocks 0/3)  zwin 0/2  syn 1/1 fin 1/1 rst 0/0

24 packets, 0 malformed, reader: ok
```

tshark 4.2.2 marks the same frames as Dup ACK (4), Previous segment not
captured, Retransmission and ZeroWindow (2).

## Testing

| Suite | What it does |
|-------|--------------|
| `tests/unit_tests.c` | 39 tests, 123,771 checks. Each layer; malformed headers; every prefix length of three complete frames (VLAN+QinQ/IPv4 options/TCP options, UDP, IPv6 ext header/TCP); 100,000 random mutations; pcap reader in all four byte-order/precision variants with truncation at every byte of the last record; flow tracker states. Frames are parsed from exact-size heap copies so ASan reports any read past the capture. |
| `tests/py/` | 63 pytest tests. scapy builds each pcap, the CLI runs in JSON mode, and every reported packet is compared field by field with scapy's dissection of the same bytes. tshark is a second reference: per-packet TCP analysis events, SACK edges, window scale, VLAN IDs, fragment offsets, IP header length, checksum status, and the core fields of a 500-packet randomized run. Includes live capture on loopback (skipped without CAP_NET_RAW). |
| Sanitizers | `make test` runs the unit tests a second time built with `-fsanitize=address,undefined -fno-sanitize-recover=all`, and runs the whole pytest suite against the sanitizer build of the CLI. |
| Fuzzing | `fuzz/fuzz_parse.c` (parser + flow tracker, aborts on any offset or length outside the capture) and `fuzz/fuzz_pcap.c` (reader + parser + flow table). `make fuzz` (libFuzzer), `make fuzz-afl` + `fuzz/run_campaign.sh` (AFL++ then libFuzzer). |
| Warnings | everything builds with `-std=c11 -Wall -Wextra -Werror -pedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wcast-align` under gcc 13 and clang 18. |

The TCP edge cases in `tests/py/test_tcp_edge_cases.py` (24 tests):
handshake options and clean close, RTO retransmission, SYN retransmission,
FIN retransmission, reordering within the 3 ms window, a lost segment
resent after 200 ms, duplicate ACKs followed by a fast retransmit, SACK with
1 to 3 blocks, 4 SACK blocks filling the option space, window scale 0/1/7/14,
a peer that omits window scale, zero window and window update, zero- and
one-byte keep-alives, RST abort, RST to a SYN on a closed port, simultaneous
close, sequence wraparound, timestamp option values, URG/ECE/CWR flags, 50
interleaved flows, and initiator detection independent of address order.
Every one of them also compares per-packet events with tshark.

## Results

All numbers below were measured in the container this was developed in, on
2026-10-25. It is a shared cloud VM, so timings vary between runs; the
spread is reported rather than hidden.

**Machine:** Intel Xeon Processor @ 2.80GHz (family 6, model 85, stepping 7:
Cascade Lake), 2 vCPUs under KVM, 2 MiB L2 per core, 33 MiB L3, 8 GB RAM.
Linux 6.18, Ubuntu 24.04, gcc 13.3.0, `-O2 -g`, no `-march=native`.

**Benchmark** (`./build/bench_parse 11 1`): 4096 frames, mean 479.3 bytes,
each starting on a 64-byte boundary; mix by count: 40.7% TCP pure ACK with
timestamps (66 B), 4.9% SYN with 5 options (74 B), 24.0% full-size TCP data
(1514 B), 5.5% ACK with 2 SACK blocks (86 B), 10.4% UDP (106 B), 9.9%
802.1Q-tagged TCP (578 B), 4.7% IPv6 TCP (286 B). Pinned to CPU 1 with
`sched_setaffinity`. Each mode is timed 11 times (about 0.3 s per run); the
table shows the median of those 11 for each of three separate invocations.

| Mode | Median ns/pkt (3 invocations) | Mpps at those medians | Fastest single run |
|------|------------------------------|-----------------------|--------------------|
| Parse only | 23.49 / 22.19 / 21.62 | 42.6 / 45.1 / 46.2 | 20.10 ns |
| Parse + IPv4 header checksum | 40.36 / 36.46 / 26.91 | 24.8 / 27.4 / 37.2 | 25.94 ns |
| Parse + flow tracking (1024 flows) | 103.89 / 86.21 / 90.77 | 9.6 / 11.6 / 11.0 | 82.28 ns |
| Parse + IPv4 and TCP/UDP checksums | 107.77 / 124.82 / 161.22 | 9.3 / 8.0 / 6.2 | 104.37 ns |

The full-checksum mode reads every payload byte, so it scales with the
packet mix (mean 479 bytes) rather than with header count.

**Correctness and robustness**

| Measure | Result |
|---------|--------|
| C unit tests | 39 tests, 123,771 checks, all pass (gcc 13 and clang 18; plain and ASan+UBSan) |
| pytest | 63 tests, all pass against the ASan+UBSan CLI built with gcc and, separately, with clang; 24 of them are TCP edge cases |
| References | scapy 2.8.0 for every packet; tshark 4.2.2 for TCP analysis events and selected fields |
| Line coverage, library (`src/`) | 97.6% (700 of 717 lines), gcc `--coverage` + gcovr, unit tests + pytest |
| Branch coverage, library (`src/`) | 93.4% (409 of 438 branches) |
| Function coverage, library | 100% (45 of 45) |
| Coverage, CLI (`tools/netparse.c`) | 81.1% of lines, 69.4% of branches |
| Fuzzers | AFL++ 4.09c (afl-clang-fast, ASan+UBSan) and libFuzzer (clang 18, ASan+UBSan) |
| Fuzz time | 26 CPU-minutes: AFL++ 540 s per target, then libFuzzer 241 s per target, two targets in parallel each time |
| Fuzz executions | 161,746,091 in total: AFL++ fuzz_parse 34,295,060, fuzz_pcap 34,612,579; libFuzzer fuzz_parse 70,510,956, fuzz_pcap 22,327,496 |
| Fuzz coverage | AFL++ edges: fuzz_parse 209 of 832, fuzz_pcap 267 of 826 (total_edges includes the instrumented harness and sanitizer runtime). libFuzzer final cov: 225 and 287 |
| Crashes, hangs, invariant violations from fuzzing | 0 |
| Defects found and fixed | 4, all in TCP analysis or capture handling, none memory-safety; see below |

Uncovered library lines are mostly allocation and `read()` failure paths in
`np_pcap_map_file`.

### Defects found

None of the fuzzers or sanitizers found a crash or an out-of-bounds read.
The defects found were semantic, mainly by the tshark comparison:

1. A repeated zero-window ACK was counted as a duplicate ACK; Wireshark does
   not count ACKs with window 0. (tshark comparison)
2. The ACK answering a keep-alive was counted as a duplicate ACK. (tshark
   comparison)
3. A zero-length keep-alive was reported as a duplicate ACK, because the
   keep-alive check only ran for segments with sequence length > 0. (unit test)
4. On loopback, AF_PACKET delivers each frame twice, so the live tracker saw
   every segment twice. Found while writing the live-capture test; with the
   fix disabled that test fails. (live test)

Each has a regression test; details are in `CHANGELOG.md`.

## Building

Requirements: gcc or clang, make, python3. For the full test suite:
`pip install scapy pytest` (add `--break-system-packages` on Ubuntu 24.04);
tshark is optional and is used when present. `make fuzz` needs clang with
compiler-rt (`libclang-rt-18-dev` on Ubuntu); `make fuzz-afl` needs AFL++;
`make coverage` needs gcovr.

```
make            # library, CLI, unit tests, benchmark -> build/
make test       # unit tests, unit tests under ASan+UBSan, pytest on the ASan CLI
make bench      # benchmark
make coverage   # gcov/gcovr summary in build-cov/coverage.txt
make fuzz FUZZ_TIME=60
make clean
```

## Limitations

- No IP reassembly: TCP/UDP headers are only read from first fragments, and
  later fragments are not attributed to a flow.
- pcapng is not read; convert with `editcap -F pcap`. Only the Ethernet and
  raw-IP link types are supported.
- The out-of-order/retransmission split uses a fixed 3 ms window, like
  Wireshark's default. It can disagree with Wireshark near that boundary,
  because Wireshark measures from the last packet that advanced the
  sequence and netparse measures from the packet that opened the hole.
  Fast and spurious retransmissions are not distinguished.
- At most 8 holes are tracked per direction; further gaps are counted in
  `holes_lost` and segments that later fill them are reported as
  retransmissions.
- The flow table has a fixed size (65,536 slots in the CLI) and no expiry.
- Flow tracking costs roughly 4x the parse itself in the benchmark. The
  per-flow state is 512 bytes, so 1024 flows do not fit in L1; a
  hot/cold split of `np_flow` would be the next thing to try.
- The benchmark parses frames already in cache-warm memory. It does not
  include NIC, DMA or kernel costs, and the numbers come from a shared VM.
- Live capture is Linux-only, needs CAP_NET_RAW, and has no BPF filter.

## License

MIT. Copyright (c) 2026 Karthik Vetrivel.
