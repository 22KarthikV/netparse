#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write examples/sample.pcap: one TCP connection with a lost segment, a
fast retransmit, SACK, duplicate ACKs and a zero window, plus a VLAN-tagged
UDP flow and an IPv4 fragment pair."""
from pathlib import Path

from scapy.all import IP, TCP, UDP, Dot1Q, Ether, Raw, fragment, wrpcap

C, S, T0 = "10.0.0.1", "10.0.0.2", 1700000000.0
SYN = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (100, 0)), ("NOP", None), ("WScale", 7)]
pk, t = [], [T0]


def add(p, dt=0.0001):
    p = Ether(bytes(p))
    t[0] += dt
    p.time = t[0]
    pk.append(p)


def c2s(fl, seq, ack, data=b"", **kw):
    return Ether() / IP(src=C, dst=S) / TCP(sport=40000, dport=8080, flags=fl, seq=seq, ack=ack,
                                            **kw) / Raw(data)


def s2c(fl, seq, ack, data=b"", **kw):
    return Ether() / IP(src=S, dst=C) / TCP(sport=8080, dport=40000, flags=fl, seq=seq, ack=ack,
                                            **kw) / Raw(data)


add(c2s("S", 1000, 0, options=SYN))
add(s2c("SA", 9000, 1001, options=SYN), 0.0002)
add(c2s("A", 1001, 9001))
for i in range(5):
    if i != 1:  # segment 2 is lost before the capture point
        add(c2s("A", 1001 + i * 1000, 9001, b"x" * 1000))
    sack = [] if i < 2 else [("NOP", None), ("NOP", None), ("SAck", (3001, 1001 + (i + 1) * 1000))]
    add(s2c("A", 9001, 2001, options=sack), 0.00005)
add(c2s("A", 2001, 9001, b"y" * 1000), 0.02)        # fast retransmit
add(s2c("A", 9001, 6001, window=0), 0.0002)           # receiver full
add(s2c("A", 9001, 6001, window=0), 0.2)
add(s2c("A", 9001, 6001, window=512), 0.1)            # window update
add(c2s("FA", 6001, 9001))
add(s2c("FA", 9001, 6002))
add(c2s("A", 6002, 9002))
for i in range(3):
    add(Ether() / Dot1Q(vlan=200, prio=4) / IP(src="10.0.1.5", dst="239.1.1.1") /
        UDP(sport=30001, dport=30001) / Raw(b"md%04d" % i + b"\x00" * 50))
for f in fragment(IP(src=C, dst=S, id=4242) / UDP(sport=5000, dport=5001) / Raw(b"F" * 2000),
                  fragsize=1400):
    add(Ether() / f)
out = Path(__file__).with_name("sample.pcap")
wrpcap(str(out), pk)
print(f"wrote {out} ({len(pk)} packets)")
