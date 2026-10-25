#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate the small seed corpora in fuzz/corpus/ with scapy."""
import struct
import sys
from pathlib import Path

from scapy.all import (IP, IPv6, TCP, UDP, Dot1AD, Dot1Q, Ether, IPOption_RR, IPv6ExtHdrFragment,
                       IPv6ExtHdrHopByHop, Raw, fragment, raw)

out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "corpus")
SYN = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]
frames = {
    "tcp_syn": Ether() / IP() / TCP(flags="S", options=SYN),
    "tcp_sack": Ether() / IP() / TCP(flags="A", options=[("NOP", None), ("NOP", None),
                                                         ("SAck", (1, 2, 3, 4, 5, 6))]),
    "tcp_data": Ether() / IP() / TCP(flags="PA") / Raw(b"x" * 64),
    "udp": Ether() / IP() / UDP() / Raw(b"u" * 16),
    "vlan": Ether() / Dot1Q(vlan=5) / IP() / TCP(),
    "qinq": Ether() / Dot1AD(vlan=1) / Dot1Q(vlan=2) / IP() / UDP(),
    "ipopts": Ether() / IP(options=[IPOption_RR(routers=["1.2.3.4"])]) / TCP(),
    "frag_later": Ether() / fragment(IP() / UDP() / Raw(b"f" * 100), fragsize=64)[1],
    "ipv6_tcp": Ether() / IPv6() / TCP(flags="S", options=SYN),
    "ipv6_ext": Ether() / IPv6() / IPv6ExtHdrHopByHop() / IPv6ExtHdrFragment() / UDP(),
}
pp = out / "fuzz_parse"
pp.mkdir(parents=True, exist_ok=True)
for name, f in frames.items():
    (pp / name).write_bytes(b"\x03" + raw(f))          # eth entry, all checksums
(pp / "raw_ip").write_bytes(b"\x80" + raw(IP() / TCP()))  # raw-IP entry


def pcap(recs, magic=0xA1B2C3D4, endian="<", linktype=1):
    b = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, r in enumerate(recs):
        b += struct.pack(endian + "IIII", i, 0, len(r), len(r)) + r
    return b


pc = out / "fuzz_pcap"
pc.mkdir(parents=True, exist_ok=True)
flow = [raw(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, flags=fl, seq=s,
                                                              ack=a) / Raw(b"d" * n))
        for fl, s, a, n in [("S", 0, 0, 0), ("A", 1, 1, 10), ("A", 21, 1, 10), ("A", 11, 1, 10),
                            ("A", 1, 1, 10), ("F", 31, 1, 0)]]
(pc / "le_us").write_bytes(pcap(flow))
(pc / "be_ns").write_bytes(pcap(flow[:3], magic=0xA1B23C4D, endian=">"))
(pc / "rawip").write_bytes(pcap([raw(IP() / UDP())], linktype=101))
(pc / "all_frames").write_bytes(pcap([raw(f) for f in frames.values()]))
print(f"wrote seeds to {out}")
