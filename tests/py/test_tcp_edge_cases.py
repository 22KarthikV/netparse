# SPDX-License-Identifier: MIT
"""TCP edge cases. Each test writes a pcap with scapy, runs the CLI, checks
every packet against scapy's dissection, checks the flow statistics against
the counts the scenario was built to produce, and (if installed) checks the
per-packet TCP analysis events against tshark."""
import pytest
from npharness import (IP, TCP, Ether, Raw, check_events_vs_tshark, compare_all,
                       flow_by_ports, stamp, tshark_fields, write_pcap, TSHARK)

C, S = "10.1.0.1", "10.1.0.2"
SYN_OPTS = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000, 0)), ("NOP", None),
            ("WScale", 7)]


class Conn:
    """Builds both directions of one TCP connection."""

    def __init__(self, cport=40000, sport=443, cisn=1000, sisn=50000, src=C, dst=S):
        self.cp, self.sp = cport, sport
        self.c, self.s = cisn, sisn
        self.src, self.dst = src, dst

    def pkt(self, from_client, flags, seq, ack, data=b"", win=65535, opts=None, t=None):
        if from_client:
            ip = IP(src=self.src, dst=self.dst)
            tcp = TCP(sport=self.cp, dport=self.sp)
        else:
            ip = IP(src=self.dst, dst=self.src)
            tcp = TCP(sport=self.sp, dport=self.cp)
        tcp.flags, tcp.seq, tcp.ack, tcp.window = flags, seq, ack, win
        tcp.options = opts or []
        p = Ether() / ip / tcp
        if data:
            p = p / Raw(data)
        p = Ether(bytes(p))  # freeze checksums/lengths
        p._np_t = t
        return p

    def handshake(self, copts=SYN_OPTS, sopts=SYN_OPTS):
        out = [self.pkt(True, "S", self.c, 0, opts=copts),
               self.pkt(False, "SA", self.s, self.c + 1, opts=sopts),
               self.pkt(True, "A", self.c + 1, self.s + 1)]
        self.c += 1
        self.s += 1
        return out


def run_case(tmp_path, pkts, gap=0.0001):
    stamp(pkts, gap=gap)
    path = tmp_path / "case.pcap"
    write_pcap(path, pkts)
    jp, flows, summ = compare_all(path, pkts)
    check_events_vs_tshark(path, jp)
    return jp, flows, summ


def dirs(flow):
    return flow["a_to_b"], flow["b_to_a"]


def test_handshake_options_and_clean_close(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "PA", k.c, k.s, b"x" * 300))
    p.append(k.pkt(False, "A", k.s, k.c + 300))
    p.append(k.pkt(True, "FA", k.c + 300, k.s))
    p.append(k.pkt(False, "FA", k.s, k.c + 301))
    p.append(k.pkt(True, "A", k.c + 301, k.s + 1))
    jp, flows, summ = run_case(tmp_path, p)
    assert summ["packets"] == 8 and summ["errors"] == {}
    assert jp[0]["tcp"]["opts"] == {"mss": 1460, "sack_ok": True, "ts": [1000, 0],
                                    "wscale": 7}
    a, b = dirs(flows[0])
    assert flows[0]["a"] == f"{C}:40000"
    assert (a["syn"], a["fin"], b["syn"], b["fin"]) == (1, 1, 1, 1)
    assert (a["mss"], a["wscale"]) == (1460, 7)
    assert a["payload_bytes"] == 300
    assert a["retransmits"] == a["out_of_order"] == b["dup_acks"] == 0


def test_rto_retransmission(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "PA", k.c, k.s, b"a" * 1000))
    p.append(k.pkt(True, "PA", k.c, k.s, b"a" * 1000, t=0.300))  # RTO
    p.append(k.pkt(False, "A", k.s, k.c + 1000, t=0.310))
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[4]["events"] == ["retransmission"]
    a, _ = dirs(flows[0])
    assert a["retransmits"] == 1 and a["out_of_order"] == 0


def test_syn_retransmission(tmp_path):
    k = Conn()
    p = [k.pkt(True, "S", 1000, 0, opts=SYN_OPTS),
         k.pkt(True, "S", 1000, 0, opts=SYN_OPTS, t=1.0),
         k.pkt(False, "SA", 50000, 1001, opts=SYN_OPTS, t=1.01)]
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[1]["events"] == ["retransmission"]
    assert dirs(flows[0])[0]["syn"] == 2


def test_reordering_within_window(tmp_path):
    """Segment 2 arrives before segment 1, 100 us apart: out-of-order."""
    k = Conn()
    p = k.handshake()
    s1 = k.pkt(True, "A", k.c, k.s, b"1" * 500)
    s2 = k.pkt(True, "A", k.c + 500, k.s, b"2" * 500)
    s3 = k.pkt(True, "A", k.c + 1000, k.s, b"3" * 500)
    p += [s2, s1, s3]
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[3]["events"] == ["gap"]
    assert jp[4]["events"] == ["out-of-order"]
    assert jp[5]["events"] == []
    a, _ = dirs(flows[0])
    assert (a["out_of_order"], a["retransmits"], a["gaps"]) == (1, 0, 1)


def test_lost_then_retransmitted_after_window(tmp_path):
    """A segment missing from the capture and resent 200 ms later fills the
    hole but is a retransmission, not reordering."""
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "A", k.c + 500, k.s, b"2" * 500))  # seg 1 lost
    p.append(k.pkt(False, "A", k.s, k.c))                   # ack does not advance
    p.append(k.pkt(True, "A", k.c, k.s, b"1" * 500, t=0.2))
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[5]["events"] == ["retransmission"]
    a, _ = dirs(flows[0])
    assert (a["retransmits"], a["out_of_order"]) == (1, 0)


def test_duplicate_acks_and_fast_retransmit(tmp_path):
    k = Conn()
    p = k.handshake()
    base = k.c
    for i in range(5):
        if i == 1:
            continue  # lost before the capture point
        p.append(k.pkt(True, "A", base + i * 100, k.s, bytes([65 + i]) * 100))
        p.append(k.pkt(False, "A", k.s, base + (100 if i else 100)))
    p.append(k.pkt(True, "A", base + 100, k.s, b"B" * 100, t=0.05))  # fast retransmit
    p.append(k.pkt(False, "A", k.s, base + 500, t=0.051))
    jp, flows, _ = run_case(tmp_path, p)
    a, b = dirs(flows[0])
    # Server ACKs 100 four times: the first is new, the next three are dups.
    assert b["dup_acks"] == 3
    assert a["retransmits"] == 1
    assert [j["n"] for j in jp if "dup-ack" in j["events"]] == [7, 9, 11]


def test_sack_blocks(tmp_path):
    k = Conn()
    p = k.handshake()
    base = k.c
    p.append(k.pkt(True, "A", base, k.s, b"a" * 100))
    # 100..200 lost; 200..300 and 400..500 arrive; 300..400 lost
    p.append(k.pkt(True, "A", base + 200, k.s, b"c" * 100))
    p.append(k.pkt(False, "A", k.s, base + 100, opts=[("SAck", (base + 200, base + 300))]))
    p.append(k.pkt(True, "A", base + 400, k.s, b"e" * 100))
    p.append(k.pkt(False, "A", k.s, base + 100,
                   opts=[("NOP", None), ("NOP", None),
                         ("SAck", (base + 400, base + 500, base + 200, base + 300))]))
    p.append(k.pkt(False, "A", k.s, base + 100,
                   opts=[("NOP", None), ("NOP", None),
                         ("SAck", (base + 400, base + 500, base + 200, base + 300,
                                   base + 600, base + 700))]))
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[5]["tcp"]["opts"]["sack"] == [[base + 200, base + 300]]
    assert jp[7]["tcp"]["opts"]["sack"] == [[base + 400, base + 500], [base + 200, base + 300]]
    assert len(jp[8]["tcp"]["opts"]["sack"]) == 3
    _, b = dirs(flows[0])
    assert (b["sack_packets"], b["sack_blocks"]) == (3, 6)
    if TSHARK:
        rows = tshark_fields(tmp_path / "case.pcap", ["tcp.options.sack_le", "tcp.options.sack_re"])
        for j, r in zip(jp, rows):
            sk = j["tcp"]["opts"].get("sack", [])
            le = [int(x) for x in r["tcp.options.sack_le"].split(",") if x]
            re_ = [int(x) for x in r["tcp.options.sack_re"].split(",") if x]
            assert [[x, y] for x, y in zip(le, re_)] == sk


def test_four_sack_blocks_max(tmp_path):
    """Four SACK blocks (34 bytes) plus 2 NOPs: the most that fits in 40 bytes."""
    k = Conn()
    p = k.handshake()
    blocks = []
    for i in range(4):
        blocks += [k.c + 1000 * (i + 1), k.c + 1000 * (i + 1) + 100]
    p.append(k.pkt(False, "A", k.s, k.c, opts=[("NOP", None), ("NOP", None),
                                              ("SAck", tuple(blocks))]))
    jp, flows, _ = run_case(tmp_path, p)
    assert len(jp[3]["tcp"]["opts"]["sack"]) == 4
    assert jp[3]["tcp"]["doff"] == 14


@pytest.mark.parametrize("ws", [0, 1, 7, 14])
def test_window_scaling(tmp_path, ws):
    k = Conn()
    p = k.handshake(copts=[("MSS", 8960), ("WScale", ws)],
                    sopts=[("MSS", 1400), ("NOP", None), ("WScale", 2)])
    p.append(k.pkt(True, "A", k.c, k.s, b"z" * 10, win=513))
    jp, flows, _ = run_case(tmp_path, p)
    a, b = dirs(flows[0])
    assert (a["wscale"], a["mss"], b["wscale"], b["mss"]) == (ws, 8960, 2, 1400)
    assert jp[3]["tcp"]["win"] == 513
    if TSHARK:
        rows = tshark_fields(tmp_path / "case.pcap",
                             ["tcp.window_size_value", "tcp.window_size_scalefactor",
                              "tcp.options.wscale.shift"])
        assert int(rows[0]["tcp.options.wscale.shift"]) == ws
        assert int(rows[3]["tcp.window_size_scalefactor"]) == 1 << ws
        assert int(rows[3]["tcp.window_size_value"]) == 513


def test_no_window_scale_when_peer_omits(tmp_path):
    k = Conn()
    p = k.handshake(copts=[("MSS", 1460), ("WScale", 7)], sopts=[("MSS", 1460)])
    jp, flows, _ = run_case(tmp_path, p)
    a, b = dirs(flows[0])
    assert a["wscale"] == 7 and b["wscale"] == -1


def test_zero_window_and_probe(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "A", k.c, k.s, b"d" * 1000))
    p.append(k.pkt(False, "A", k.s, k.c + 1000, win=0))
    p.append(k.pkt(False, "A", k.s, k.c + 1000, win=0, t=0.2))
    p.append(k.pkt(False, "A", k.s, k.c + 1000, win=4096, t=0.4))  # window update
    p.append(k.pkt(True, "A", k.c + 1000, k.s, b"e" * 100, t=0.41))
    jp, flows, _ = run_case(tmp_path, p)
    _, b = dirs(flows[0])
    assert b["zero_windows"] == 2
    assert b["dup_acks"] == 0
    assert [j["n"] for j in jp if "zero-window" in j["events"]] == [5, 6]


def test_keepalive(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "A", k.c, k.s, b"q" * 10))
    p.append(k.pkt(False, "A", k.s, k.c + 10))
    p.append(k.pkt(True, "A", k.c + 9, k.s, t=60.0))          # zero-byte probe
    p.append(k.pkt(False, "A", k.s, k.c + 10, t=60.001))
    p.append(k.pkt(True, "A", k.c + 9, k.s, b"\x00", t=120.0))  # one-byte probe
    jp, flows, _ = run_case(tmp_path, p)
    a, _ = dirs(flows[0])
    assert a["keepalives"] == 2
    assert a["retransmits"] == 0


def test_rst_abort(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "PA", k.c, k.s, b"GET /\r\n"))
    p.append(k.pkt(False, "RA", k.s, k.c + 7, win=0))
    jp, flows, _ = run_case(tmp_path, p)
    _, b = dirs(flows[0])
    assert b["rst"] == 1
    assert b["zero_windows"] == 0  # RST with win 0 is not a zero-window event
    assert jp[4]["tcp"]["flags"] == 0x14


def test_rst_to_syn_closed_port(tmp_path):
    k = Conn(sport=9)
    p = [k.pkt(True, "S", 7, 0), k.pkt(False, "RA", 0, 8, win=0)]
    jp, flows, _ = run_case(tmp_path, p)
    a, b = dirs(flows[0])
    assert (a["syn"], b["rst"]) == (1, 1)


def test_simultaneous_close(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "FA", k.c, k.s))
    p.append(k.pkt(False, "FA", k.s, k.c))
    p.append(k.pkt(True, "A", k.c + 1, k.s + 1))
    p.append(k.pkt(False, "A", k.s + 1, k.c + 1))
    jp, flows, _ = run_case(tmp_path, p)
    a, b = dirs(flows[0])
    assert (a["fin"], b["fin"]) == (1, 1)
    assert a["retransmits"] == b["retransmits"] == 0


def test_fin_retransmission(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "FA", k.c, k.s))
    p.append(k.pkt(True, "FA", k.c, k.s, t=0.5))
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[4]["events"] == ["retransmission"]


def test_sequence_wraparound(tmp_path):
    k = Conn(cisn=0xFFFFFF00)
    p = k.handshake()
    seq = k.c
    for _ in range(4):
        p.append(k.pkt(True, "A", seq & 0xFFFFFFFF, k.s, b"w" * 100))
        seq += 100
    jp, flows, _ = run_case(tmp_path, p)
    assert jp[5]["tcp"]["seq"] == (0xFFFFFF01 + 200) & 0xFFFFFFFF
    a, _ = dirs(flows[0])
    assert (a["retransmits"], a["out_of_order"], a["gaps"]) == (0, 0, 0)


def test_timestamps_option_values(tmp_path):
    k = Conn()
    p = k.handshake()
    p.append(k.pkt(True, "A", k.c, k.s, b"t", opts=[("NOP", None), ("NOP", None),
                                                    ("Timestamp", (0xFFFFFFFF, 123456))]))
    jp, _, _ = run_case(tmp_path, p)
    assert jp[3]["tcp"]["opts"]["ts"] == [0xFFFFFFFF, 123456]


def test_urgent_and_ecn_flags(tmp_path):
    k = Conn()
    p = k.handshake()
    q = k.pkt(True, "UAPEC", k.c, k.s, b"!")
    q[TCP].urgptr = 1
    q = Ether(bytes(q))
    p.append(q)
    jp, _, _ = run_case(tmp_path, p)
    assert jp[3]["tcp"]["flags"] == 0xF8
    assert jp[3]["tcp"]["urg"] == 1


def test_many_flows_interleaved(tmp_path):
    p = []
    conns = [Conn(cport=30000 + i, cisn=i * 1000003) for i in range(50)]
    for k in conns:
        p += k.handshake()
    for k in conns:
        p.append(k.pkt(True, "A", k.c, k.s, b"m" * 64))
    jp, flows, summ = run_case(tmp_path, p)
    assert summ["flows"] == 50
    for f in flows:
        a, b = dirs(f)
        assert (a["packets"], b["packets"], a["payload_bytes"]) == (3, 1, 64)
        assert a["retransmits"] == a["out_of_order"] == 0


def test_flow_direction_independent_of_address_order(tmp_path):
    """The initiator is reported first even when its address sorts higher."""
    k = Conn(src="10.9.9.9", dst="10.0.0.1", cport=50000, sport=22)
    jp, flows, _ = run_case(tmp_path, k.handshake())
    assert flows[0]["a"] == "10.9.9.9:50000"
    assert flow_by_ports(flows, 22)["a_to_b"]["syn"] == 1
