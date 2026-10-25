# Changelog

## 0.1.0 (unreleased)

First version: parser, pcap reader, flow tracker, CLI, tests, fuzzing, benchmark.

### Defects found during development and fixed

Found by comparing per-packet TCP analysis events with tshark 4.2.2 (each
fix has a regression test in `tests/py/test_tcp_edge_cases.py` or
`tests/unit_tests.c`):

1. A repeated ACK advertising a zero window was counted as a duplicate ACK.
   Wireshark does not treat zero-window ACKs as duplicates.
   (`test_zero_window_and_probe`, `test_flow_dupack_sack_zwin_keepalive`)
2. The ACK answering a TCP keep-alive was counted as a duplicate ACK.
   (`test_keepalive`)

Found by a C unit test:

3. A zero-length keep-alive probe was not recognised as a keep-alive (it was
   reported as a duplicate ACK) because the check only ran for segments with
   sequence length > 0. (`test_flow_dupack_sack_zwin_keepalive`)

Found while writing the live-capture test:

4. On loopback, AF_PACKET delivers each frame twice (outgoing and looped
   back), so the flow tracker saw every segment twice. The CLI now drops the
   `PACKET_OUTGOING` copy on `ARPHRD_LOOPBACK`, as libpcap does. With the
   filter disabled, `test_live_loopback_tcp` fails (it sees 2 SYNs instead
   of 1).

### Fuzzing

AFL++ 4.09c and libFuzzer (clang 18), both with ASan+UBSan, ran on the
parser and the pcap reader for 26 CPU-minutes in total (see README).
They found no crashes, hangs or invariant violations.
