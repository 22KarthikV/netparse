# SPDX-License-Identifier: MIT
"""VLAN, IPv4 options and fragments, IPv6, UDP, checksums, truncated and
malformed captures, pcap file variants, and a randomized differential test
against scapy (and tshark when available)."""
import random
import struct

import pytest
from npharness import (IP, IPv6, TCP, UDP, Dot1AD, Dot1Q, Ether, Raw, T0, TSHARK, compare_all,
                       compare_with_scapy, raw, run, run_text, stamp, tshark_fields,
                       write_pcap, write_raw_records)
from scapy.all import (IPOption_NOP, IPOption_RR, IPOption_Router_Alert, IPOption_Timestamp,
                       IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
                       IPv6ExtHdrRouting, fragment, fuzz)

C, S = "192.168.1.10", "192.168.1.20"


def frozen(p):
    return Ether(bytes(p))


def tcp(**kw):
    return TCP(sport=1234, dport=80, flags="A", seq=1, ack=1, **kw)


# ---- VLAN ---------------------------------------------------------------

def test_vlan_single_tag(tmp_path):
    p = [frozen(Ether() / Dot1Q(vlan=100, prio=5) / IP(src=C, dst=S) / tcp() / Raw(b"v" * 20)),
         frozen(Ether() / Dot1Q(vlan=4094, prio=0, dei=1) / IP(src=S, dst=C) / UDP(sport=53, dport=5353))]
    stamp(p)
    write_pcap(tmp_path / "v.pcap", p)
    jp, _, _ = compare_all(tmp_path / "v.pcap", p)
    assert jp[0]["vlan"][0]["vid"] == 100 and jp[0]["vlan"][0]["pcp"] == 5
    assert jp[1]["vlan"][0]["dei"] == 1
    if TSHARK:
        rows = tshark_fields(tmp_path / "v.pcap", ["vlan.id", "vlan.priority"])
        assert [int(r["vlan.id"]) for r in rows] == [100, 4094]


def test_vlan_qinq(tmp_path):
    p = [frozen(Ether() / Dot1AD(vlan=10) / Dot1Q(vlan=20) / IP(src=C, dst=S) / tcp()),
         frozen(Ether(type=0x8100) / Dot1Q(vlan=30) / Dot1Q(vlan=40) / IP(src=C, dst=S) / tcp())]
    stamp(p)
    write_pcap(tmp_path / "q.pcap", p)
    jp, _, _ = compare_all(tmp_path / "q.pcap", p)
    assert [v["vid"] for v in jp[0]["vlan"]] == [10, 20]
    assert jp[0]["vlan"][0]["tpid"] == 0x88A8
    assert [v["vid"] for v in jp[1]["vlan"]] == [30, 40]


def test_vlan_three_tags_rejected(tmp_path):
    p = [frozen(Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=2) / Dot1Q(vlan=3) / IP() / tcp())]
    stamp(p)
    write_pcap(tmp_path / "t.pcap", p)
    jp, _, summ = run(tmp_path / "t.pcap")
    assert jp[0]["err"] == "too many vlan tags"
    assert [v["vid"] for v in jp[0]["vlan"]] == [1, 2]


def test_non_ip_ethertypes(tmp_path):
    from scapy.all import ARP
    p = [frozen(Ether() / ARP()), frozen(Ether(type=0x88CC) / Raw(b"\x00" * 46))]
    stamp(p)
    write_pcap(tmp_path / "n.pcap", p)
    jp, flows, _ = run(tmp_path / "n.pcap")
    assert [j["layers"] for j in jp] == [["eth"], ["eth"]]
    assert [j["ethertype"] for j in jp] == [0x0806, 0x88CC]
    assert flows == []


# ---- IPv4 options / fragments -------------------------------------------

@pytest.mark.parametrize("opts", [
    [IPOption_RR(routers=["1.1.1.1", "2.2.2.2"])],
    [IPOption_Router_Alert()],
    [IPOption_NOP(), IPOption_Timestamp(flg=0, timestamp=[1234])],
    [IPOption_RR(routers=["0.0.0.0"] * 9)],  # 40 bytes of options, IHL 15
])
def test_ip_options(tmp_path, opts):
    p = [frozen(Ether() / IP(src=C, dst=S, options=opts) / tcp() / Raw(b"o" * 8))]
    stamp(p)
    write_pcap(tmp_path / "o.pcap", p)
    jp, _, _ = compare_all(tmp_path / "o.pcap", p)
    assert jp[0]["ip"]["opt_len"] == p[0][IP].ihl * 4 - 20 > 0
    assert jp[0]["ip"]["csum_bad"] is False
    assert jp[0]["flags"]["l4_csum_bad"] is False
    if TSHARK:
        rows = tshark_fields(tmp_path / "o.pcap", ["ip.hdr_len", "tcp.srcport"])
        assert int(rows[0]["ip.hdr_len"]) == p[0][IP].ihl * 4
        assert int(rows[0]["tcp.srcport"]) == 1234


def test_ipv4_fragments_tcp_and_udp(tmp_path):
    big_tcp = Ether() / IP(src=C, dst=S, id=777) / tcp() / Raw(bytes(range(256)) * 12)
    big_udp = Ether() / IP(src=C, dst=S, id=778) / UDP(sport=9, dport=9) / Raw(b"u" * 3000)
    frags = []
    for big in (big_tcp, big_udp):
        for f in fragment(big[IP], fragsize=1200):
            frags.append(frozen(Ether() / f))
    stamp(frags)
    write_pcap(tmp_path / "f.pcap", frags)
    jp, flows, _ = compare_all(tmp_path / "f.pcap", frags)
    for j, f in zip(jp, frags):
        assert j["flags"]["frag"] is True
        if f[IP].frag == 0:
            assert ("tcp" in j["layers"]) or ("udp" in j["layers"])
        else:
            assert "tcp" not in j["layers"] and "udp" not in j["layers"]
            assert j["payload_len"] == f[IP].len - 20
    # first UDP fragment: udp.len is the reassembled length
    first_udp = next(j for j in jp if "udp" in j["layers"])
    assert first_udp["udp"]["len"] == 3008
    if TSHARK:
        rows = tshark_fields(tmp_path / "f.pcap", ["ip.frag_offset", "ip.flags.mf", "ip.id"])
        for j, r in zip(jp, rows):
            # Wireshark 4.x reports ip.frag_offset in 8-byte units.
            assert int(r["ip.frag_offset"]) * 8 == j["ip"]["frag_off"]
            mf = r["ip.flags.mf"]
            assert (mf in ("1", "True")) == bool(j["ip"]["mf"])


def test_ping_of_death_fragment(tmp_path):
    p = frozen(Ether() / IP(src=C, dst=S, frag=8189, proto=17) / Raw(b"x" * 100))
    stamp([p])
    write_pcap(tmp_path / "pod.pcap", [p])
    jp, _, _ = run(tmp_path / "pod.pcap")
    assert jp[0]["err"] == "ipv4 fragment exceeds 65535 bytes"


# ---- IPv6 -----------------------------------------------------------------

def test_ipv6_tcp_udp_and_ext_headers(tmp_path):
    a, b = "2001:db8::1", "2001:db8:0:1::2"
    p = [frozen(Ether() / IPv6(src=a, dst=b, fl=0x12345, tc=0x28) / tcp() / Raw(b"6" * 30)),
         frozen(Ether() / IPv6(src=b, dst=a) / UDP(sport=546, dport=547) / Raw(b"d" * 10)),
         frozen(Ether() / IPv6(src=a, dst=b) / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
                / tcp()),
         frozen(Ether() / IPv6(src=a, dst=b) / IPv6ExtHdrRouting() / UDP(sport=1, dport=2)),
         frozen(Ether() / IPv6(src=a, dst=b) / IPv6ExtHdrFragment(offset=0, m=1, id=99)
                / tcp() / Raw(b"f" * 8))]
    stamp(p)
    write_pcap(tmp_path / "v6.pcap", p)
    jp, flows, _ = compare_all(tmp_path / "v6.pcap", p)
    assert [j["ip"]["ext_count"] for j in jp] == [0, 0, 2, 1, 1]
    assert jp[4]["flags"]["frag"] is True and "tcp" in jp[4]["layers"]
    assert all(not j["flags"]["l4_csum_bad"] for j in jp)
    assert any(f["a"].startswith("[2001:db8::1]") for f in flows)


def test_ipv6_later_fragment(tmp_path):
    p = [frozen(Ether() / IPv6(src="fe80::1", dst="fe80::2") /
                IPv6ExtHdrFragment(offset=100, m=0, id=5, nh=6) / Raw(b"r" * 40))]
    stamp(p)
    write_pcap(tmp_path / "v6f.pcap", p)
    jp, _, _ = run(tmp_path / "v6f.pcap")
    assert jp[0]["err"] == "ok"
    assert jp[0]["ip"]["frag_off"] == 800
    assert jp[0]["layers"] == ["eth", "ipv6"]


# ---- UDP and checksums -----------------------------------------------------

def test_udp_variants(tmp_path):
    p = [frozen(Ether() / IP(src=C, dst=S) / UDP(sport=319, dport=320) / Raw(b"p" * 44)),
         frozen(Ether() / IP(src=C, dst=S) / UDP(sport=5000, dport=5001, chksum=0) / Raw(b"z")),
         frozen(Ether() / IP(src=C, dst=S) / UDP(sport=1, dport=2))]  # empty payload
    stamp(p)
    write_pcap(tmp_path / "u.pcap", p)
    jp, flows, _ = compare_all(tmp_path / "u.pcap", p)
    assert [j["payload_len"] for j in jp] == [44, 1, 0]
    assert all(not j["flags"]["l4_csum_bad"] for j in jp)
    assert len(flows) == 3 and all(f["proto"] == "udp" for f in flows)


def test_bad_checksums_flagged(tmp_path):
    good = Ether() / IP(src=C, dst=S) / tcp() / Raw(b"c" * 9)
    p = [frozen(good),
         frozen(Ether() / IP(src=C, dst=S, chksum=0x1234) / tcp() / Raw(b"c" * 9)),
         frozen(Ether() / IP(src=C, dst=S) / TCP(sport=1, dport=2, chksum=0xBEEF) / Raw(b"c")),
         frozen(Ether() / IP(src=C, dst=S) / UDP(sport=1, dport=2, chksum=0x1111) / Raw(b"c"))]
    stamp(p)
    write_pcap(tmp_path / "c.pcap", p)
    jp, _, _ = compare_all(tmp_path / "c.pcap", p)
    assert [j["ip"]["csum_bad"] for j in jp] == [False, True, False, False]
    assert [j["flags"]["l4_csum_bad"] for j in jp] == [False, False, True, True]
    # -n disables verification
    jp2, _, _ = run(tmp_path / "c.pcap", "-n")
    assert not any(j["ip"]["csum_bad"] or j["flags"]["l4_csum_bad"] for j in jp2)
    if TSHARK:
        import subprocess
        out = subprocess.run([TSHARK, "-n", "-r", str(tmp_path / "c.pcap"),
                              "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE",
                              "-o", "udp.check_checksum:TRUE", "-Y",
                              "ip.checksum.status == 0 || tcp.checksum.status == 0 || "
                              "udp.checksum.status == 0", "-T", "fields", "-e", "frame.number"],
                             capture_output=True, text=True)
        assert {int(x) for x in out.stdout.split()} == {2, 3, 4}


def test_ethernet_padding(tmp_path):
    p = Ether() / IP(src=C, dst=S) / tcp()
    b = raw(p) + b"\x00" * 6  # 54 -> 60 bytes
    write_raw_records(tmp_path / "pad.pcap", [(b, 60, T0)])
    jp, _, _ = run(tmp_path / "pad.pcap")
    assert jp[0]["err"] == "ok"
    assert jp[0]["flags"]["padded"] is True
    assert jp[0]["payload_len"] == 0
    assert jp[0]["flags"]["l4_csum_bad"] is False
    compare_with_scapy(jp[0], b)


# ---- truncated captures (snaplen) -----------------------------------------

def test_truncated_capture_every_snaplen(tmp_path):
    """Write the same frame cut at every length, as tcpdump -s N would."""
    p = Ether() / Dot1Q(vlan=7) / IP(src=C, dst=S, options=[IPOption_Router_Alert()]) / \
        TCP(sport=1, dport=2, options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 3)]) / \
        Raw(b"t" * 40)
    full = raw(p)
    hdr_end = 18 + 24 + 32
    recs = [(full[:n], len(full), T0 + n * 1e-6) for n in range(len(full) + 1)]
    write_raw_records(tmp_path / "trunc.pcap", recs, snaplen=len(full))
    jp, _, summ = run(tmp_path / "trunc.pcap")
    assert summ["status"] == "ok" and len(jp) == len(full) + 1
    for n, j in enumerate(jp):
        assert j["caplen"] == n and j["len"] == len(full)
        if n < 14:
            assert j["err"] == "truncated ethernet header"
        elif n < 18:
            assert j["err"] == "truncated vlan tag"
        elif n < 18 + 24:
            assert j["err"] == "truncated ipv4 header"
        elif n < hdr_end:
            assert j["err"] == "truncated tcp header"
        else:
            assert j["err"] == "ok"
            assert j["payload_len"] == 40 and j["payload_caplen"] == n - hdr_end
            assert j["flags"]["truncated"] == (n < len(full))
            assert j["flags"]["l4_csum_bad"] is False  # not verifiable, not flagged
            compare_with_scapy(j, full[:n]) if n == len(full) else None


def test_truncated_pcap_file(tmp_path):
    p = [frozen(Ether() / IP(src=C, dst=S) / tcp()) for _ in range(3)]
    stamp(p)
    write_pcap(tmp_path / "ok.pcap", p)
    data = (tmp_path / "ok.pcap").read_bytes()
    (tmp_path / "cut.pcap").write_bytes(data[:-10])
    jp, _, summ = run(tmp_path / "cut.pcap")
    assert len(jp) == 2
    assert summ["status"] == "truncated record data"
    (tmp_path / "cut2.pcap").write_bytes(data[:24 + 2 * (16 + 54) + 7])
    _, _, summ = run(tmp_path / "cut2.pcap")
    assert summ["status"] == "truncated record header"


# ---- malformed headers -----------------------------------------------------

@pytest.mark.parametrize("mut,err", [
    (lambda b: b[:14] + bytes([0x65]) + b[15:], "bad ipv4 version"),
    (lambda b: b[:14] + bytes([0x43]) + b[15:], "bad ipv4 ihl"),
    (lambda b: b[:16] + struct.pack(">H", 10) + b[18:], "bad ipv4 total length"),
    (lambda b: b[:46] + bytes([0x30]) + b[47:], "bad tcp data offset"),
    (lambda b: b[:46] + bytes([0xF0]) + b[47:], "bad tcp data offset"),
])
def test_malformed_headers(tmp_path, mut, err):
    b = mut(raw(Ether() / IP(src=C, dst=S) / tcp() / Raw(b"m" * 10)))
    write_raw_records(tmp_path / "m.pcap", [(b, len(b), T0)])
    jp, flows, summ = run(tmp_path / "m.pcap")
    assert jp[0]["err"] == err
    assert flows == []
    assert summ["errors"] == {err: 1}


@pytest.mark.parametrize("opt", [
    b"\x02\x03\x05\x00",         # MSS with length 3
    b"\x03\x04\x07\x00",         # wscale with length 4
    b"\x05\x06\x00\x00\x00\x00\x00\x00",  # SACK with one partial block
    b"\x08\x0a\x00\x00",         # timestamp overruns option space
    b"\x1e\x00\x00\x00",         # length 0
])
def test_malformed_tcp_options(tmp_path, opt):
    t = TCP(sport=1, dport=2, flags="S")
    t.dataofs = 5 + len(opt) // 4
    b = raw(Ether() / IP(src=C, dst=S) / t / Raw(opt))
    write_raw_records(tmp_path / "mo.pcap", [(b, len(b), T0)])
    jp, _, _ = run(tmp_path / "mo.pcap")
    assert jp[0]["err"] == "malformed tcp options"
    assert jp[0]["layers"] == ["eth", "ipv4"]


def test_udp_length_errors(tmp_path):
    good = raw(Ether() / IP(src=C, dst=S) / UDP(sport=1, dport=2) / Raw(b"u" * 10))
    short = good[:38] + struct.pack(">H", 4) + good[40:]
    long_ = good[:38] + struct.pack(">H", 200) + good[40:]
    write_raw_records(tmp_path / "ul.pcap", [(short, len(short), T0), (long_, len(long_), T0)])
    jp, _, _ = run(tmp_path / "ul.pcap")
    assert [j["err"] for j in jp] == ["bad udp length", "bad udp length"]


# ---- pcap file format variants ---------------------------------------------

@pytest.mark.parametrize("nano", [False, True])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcap_variants(tmp_path, nano, endian):
    p = [frozen(Ether() / IP(src=C, dst=S) / tcp() / Raw(b"%d" % i)) for i in range(5)]
    from decimal import Decimal
    for i, q in enumerate(p):
        q.time = Decimal(T0 + i) + Decimal("0.123456789")
    write_pcap(tmp_path / "pv.pcap", p, nano=nano, endianness=endian)
    raw_hdr = (tmp_path / "pv.pcap").read_bytes()[:4]
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    assert raw_hdr == struct.pack(endian + "I", magic)
    jp, _, summ = compare_all(tmp_path / "pv.pcap", p)
    assert summ["status"] == "ok"
    for i, j in enumerate(jp):
        assert j["ts_sec"] == T0 + i
        if nano:
            assert j["ts_nsec"] == 123456789
        else:
            assert j["ts_nsec"] == 123457000


def test_raw_ip_linktype(tmp_path):
    pk = IP(src=C, dst=S) / tcp() / Raw(b"raw")
    b = raw(pk)
    write_raw_records(tmp_path / "rawip.pcap", [(b, len(b), T0)], linktype=101)
    jp, _, _ = run(tmp_path / "rawip.pcap")
    assert jp[0]["layers"] == ["ipv4", "tcp"]
    assert jp[0]["payload_len"] == 3


def test_rejects_pcapng(tmp_path):
    from scapy.all import wrpcapng
    wrpcapng(str(tmp_path / "x.pcapng"), [Ether() / IP() / tcp()])
    rc, out, err = run_text(tmp_path / "x.pcapng")
    assert rc == 2 and "bad magic" in err


# ---- randomized differential test -----------------------------------------

def test_random_differential_vs_scapy(tmp_path):
    """500 randomized but well-formed packets: every field the CLI reports
    must equal scapy's dissection (and tshark's for the core fields)."""
    rnd = random.Random(1234)
    pkts = []
    for i in range(500):
        l2 = Ether()
        if rnd.random() < 0.2:
            l2 = l2 / Dot1Q(vlan=rnd.randrange(1, 4095), prio=rnd.randrange(8))
        if rnd.random() < 0.8:
            l3 = IP(src="10.%d.%d.%d" % (rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)),
                    dst="10.0.0.%d" % rnd.randrange(256), ttl=rnd.randrange(1, 256),
                    id=rnd.randrange(65536), tos=rnd.randrange(256),
                    flags=rnd.choice([0, 2]))
        else:
            l3 = IPv6(src="2001:db8::%x" % rnd.randrange(65536), dst="2001:db8::1",
                      hlim=rnd.randrange(256), fl=rnd.randrange(1 << 20))
        if rnd.random() < 0.75:
            opts = []
            if rnd.random() < 0.5:
                opts.append(("MSS", rnd.randrange(65536)))
            if rnd.random() < 0.3:
                opts.append(("WScale", rnd.randrange(15)))
            if rnd.random() < 0.3:
                opts.append(("SAckOK", b""))
            if rnd.random() < 0.5:
                opts.append(("Timestamp", (rnd.randrange(1 << 32), rnd.randrange(1 << 32))))
            if rnd.random() < 0.2 and len(opts) <= 1:
                n = rnd.randrange(1, 4)
                opts.append(("SAck", tuple(rnd.randrange(1 << 32) for _ in range(2 * n))))
            l4 = TCP(sport=rnd.randrange(65536), dport=rnd.randrange(65536),
                     seq=rnd.randrange(1 << 32), ack=rnd.randrange(1 << 32),
                     flags=rnd.randrange(256), window=rnd.randrange(65536),
                     urgptr=rnd.randrange(65536), options=opts)
        else:
            l4 = UDP(sport=rnd.randrange(65536), dport=rnd.randrange(65536))
        pay = Raw(bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 300))))
        pkts.append(frozen(l2 / l3 / l4 / pay))
    stamp(pkts)
    path = tmp_path / "rand.pcap"
    write_pcap(path, pkts)
    jp, _, summ = compare_all(path, pkts)
    assert summ["packets"] == 500 and summ["errors"] == {}
    if TSHARK:
        rows = tshark_fields(path, ["tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack",
                                    "tcp.window_size_value", "udp.srcport", "udp.length",
                                    "tcp.options.mss_val", "tcp.options.timestamp.tsval"])
        for j, r in zip(jp, rows):
            if "tcp" in j:
                t = j["tcp"]
                assert int(r["tcp.srcport"]) == t["sport"]
                assert int(r["tcp.dstport"]) == t["dport"]
                assert int(r["tcp.seq"]) == t["seq"]
                assert int(r["tcp.window_size_value"]) == t["win"]
                if "mss" in t["opts"]:
                    assert int(r["tcp.options.mss_val"]) == t["opts"]["mss"]
                if "ts" in t["opts"]:
                    assert int(r["tcp.options.timestamp.tsval"]) == t["opts"]["ts"][0]
            else:
                assert int(r["udp.srcport"]) == j["udp"]["sport"]
                assert int(r["udp.length"]) == j["udp"]["len"]


def test_scapy_fuzz_never_crashes(tmp_path):
    """scapy's fuzz() fills header fields with random values, producing many
    malformed packets. The CLI (under ASan when run via make test) must
    handle all of them; well-formed ones must still match scapy."""
    random.seed(99)
    pkts = []
    for i in range(400):
        base = Ether() / fuzz(IP(version=4)) / fuzz(TCP()) if i % 2 else \
            Ether() / IP() / fuzz(TCP()) / Raw(b"x" * (i % 50))
        try:
            pkts.append(raw(base))
        except Exception:
            continue
    recs = [(b, len(b), T0 + i) for i, b in enumerate(pkts)]
    write_raw_records(tmp_path / "fz.pcap", recs)
    jp, _, summ = run(tmp_path / "fz.pcap")
    assert summ["packets"] == len(pkts)
    for j, b in zip(jp, pkts):
        if j["err"] == "ok" and "tcp" in j["layers"] and IP in Ether(b) and \
                Ether(b)[IP].frag == 0 and Ether(b)[IP].ihl * 4 >= 20:
            compare_with_scapy(j, b)


# ---- text output -------------------------------------------------------------

def test_text_output_format(tmp_path):
    p = [frozen(Ether() / IP(src=C, dst=S) / TCP(sport=5555, dport=80, flags="S", seq=10,
                                                 options=[("MSS", 1460), ("WScale", 7)])),
         frozen(Ether() / IP(src=S, dst=C) / UDP(sport=53, dport=5555) / Raw(b"q" * 12))]
    p[0].time = T0 + 0.5
    p[1].time = T0 + 0.75
    write_pcap(tmp_path / "txt.pcap", p)
    rc, out, _ = run_text(tmp_path / "txt.pcap")
    lines = out.splitlines()
    assert rc == 0
    assert lines[0] == ("1700000000.500000 IP 192.168.1.10.5555 > 192.168.1.20.80: Flags [S], "
                        "seq 10, win 8192, options [mss 1460,wscale 7], length 0")
    assert lines[1] == "1700000000.750000 IP 192.168.1.20.53 > 192.168.1.10.5555: UDP, length 12"
    assert "Flows: 2" in out
    assert "2 packets, 0 malformed, reader: ok" in out


def test_read_pcap_from_pipe(tmp_path):
    """Non-regular files (pipes) are read into memory instead of mmap'd."""
    import subprocess
    from npharness import BIN
    p = [frozen(Ether() / IP(src=C, dst=S) / tcp() / Raw(b"p" * 100)) for _ in range(300)]
    stamp(p)
    write_pcap(tmp_path / "pipe.pcap", p)
    data = (tmp_path / "pipe.pcap").read_bytes()
    out = subprocess.run([BIN, "-q", "-F", "-r", "/dev/stdin"], input=data,
                         capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert b"300 packets, 0 malformed, reader: ok" in out.stdout
