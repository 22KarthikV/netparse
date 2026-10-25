# SPDX-License-Identifier: MIT
"""Helpers for the pytest suite.

scapy builds the packets and is the field-level reference: every packet the
CLI reports is compared with scapy's own dissection of the same bytes.
When tshark is installed it is used as a second reference, both for
fields and for its TCP sequence analysis (retransmission, out-of-order,
duplicate ACK, zero window, keep-alive, previous segment not captured).
"""
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

from scapy.all import (  # noqa: F401  (re-exported for tests)
    IP, IPv6, TCP, UDP, Dot1Q, Dot1AD, Ether, Raw, raw, wrpcap,
)
from scapy.utils import RawPcapWriter

ROOT = Path(__file__).resolve().parents[2]
BIN = os.environ.get("NETPARSE_BIN", str(ROOT / "build" / "netparse"))
TSHARK = shutil.which("tshark")

T0 = 1700000000


def write_pcap(path, pkts, nano=False, endianness=""):
    """Write scapy packets. pkt.time must already be set."""
    if endianness:
        w = RawPcapWriter(str(path), linktype=1, nano=nano, endianness=endianness, sync=True)
        w._write_header(None)
        for p in pkts:
            b = raw(p)
            from decimal import Decimal
            t = Decimal(str(p.time))
            sec = int(t)
            frac = int(((t - sec) * (10**9 if nano else 10**6)).to_integral_value())
            w.write_packet(b, sec=sec, usec=frac, caplen=len(b), wirelen=len(b))
        w.close()
    else:
        wrpcap(str(path), pkts, nano=nano)


def write_raw_records(path, records, snaplen=65535, linktype=1):
    """records: list of (bytes, origlen, t). Lets tests write truncated
    captures where caplen < origlen."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for data, origlen, t in records:
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), origlen))
            f.write(data)


def run(path, *args):
    """Run the CLI in JSON mode; return (packets, flows, summary)."""
    out = subprocess.run([BIN, "-j", *args, "-r", str(path)], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode in (0, 1), out.stderr
    assert "runtime error" not in out.stderr, out.stderr  # UBSan
    assert "AddressSanitizer" not in out.stderr, out.stderr
    pkts, flows, summary = [], [], None
    for line in out.stdout.splitlines():
        rec = json.loads(line)
        if rec["type"] == "pkt":
            pkts.append(rec)
        elif rec["type"] == "flow":
            flows.append(rec)
        else:
            summary = rec
    return pkts, flows, summary


def run_text(path, *args):
    out = subprocess.run([BIN, *args, "-r", str(path)], capture_output=True, text=True,
                         timeout=60)
    assert "runtime error" not in out.stderr and "AddressSanitizer" not in out.stderr
    return out.returncode, out.stdout, out.stderr


def stamp(pkts, gap=0.0001, start=T0):
    """Give packets increasing timestamps (default 100 us apart)."""
    t = start
    for p in pkts:
        if getattr(p, "_np_t", None) is not None:
            t = start + p._np_t
        p.time = t
        t += gap
    return pkts


# ---- field comparison against scapy -----------------------------------

def _tcp_opts(tcp):
    d = {}
    for k, v in tcp.options:
        if k == "MSS":
            d["mss"] = v
        elif k == "WScale":
            d["wscale"] = v
        elif k == "SAckOK":
            d["sack_ok"] = True
        elif k == "Timestamp":
            d["ts"] = list(v)
        elif k == "SAck":
            d["sack"] = [list(v[i:i + 2]) for i in range(0, len(v), 2)]
    return d


def compare_with_scapy(j, frame_bytes):
    """Assert that one CLI JSON record matches scapy's dissection."""
    s = Ether(frame_bytes)
    assert j["caplen"] == len(frame_bytes)
    vl = []
    layer = s.payload
    while isinstance(layer, (Dot1Q, Dot1AD)):
        vl.append({"vid": layer.vlan, "pcp": layer.prio, "dei": layer.dei})
        layer = layer.payload
    got_vl = [{k: v[k] for k in ("vid", "pcp", "dei")} for v in j.get("vlan", [])]
    assert got_vl == vl
    if IP in s:
        ip = s[IP]
        g = j["ip"]
        assert g["ver"] == 4
        assert (g["src"], g["dst"]) == (ip.src, ip.dst)
        assert g["ihl"] == ip.ihl
        assert g["tos"] == ip.tos
        assert g["tot_len"] == ip.len
        assert g["id"] == ip.id
        assert g["ttl"] == ip.ttl
        assert g["proto"] == ip.proto
        assert g["df"] == int(bool(ip.flags.DF))
        assert g["mf"] == int(bool(ip.flags.MF))
        assert g["frag_off"] == ip.frag * 8
        assert g["csum"] == ip.chksum
        assert g["opt_len"] == ip.ihl * 4 - 20
        l4 = ip.payload if ip.frag == 0 else None
    elif IPv6 in s:
        ip6 = s[IPv6]
        g = j["ip"]
        assert g["ver"] == 6
        assert (g["src"], g["dst"]) == (ip6.src, ip6.dst)
        assert g["plen"] == ip6.plen
        assert g["hlim"] == ip6.hlim
        assert g["tc"] == ip6.tc
        assert g["flow_label"] == ip6.fl
        l4 = None
        if TCP in s:
            l4 = s[TCP]
        elif UDP in s:
            l4 = s[UDP]
    else:
        assert "ip" not in j
        return
    if l4 is not None and isinstance(l4, TCP):
        t = j["tcp"]
        assert (t["sport"], t["dport"]) == (l4.sport, l4.dport)
        assert (t["seq"], t["ack"]) == (l4.seq, l4.ack)
        # scapy's flags field is 9 bits wide (it includes the AE/NS bit from
        # the reserved nibble); netparse reports the 8 classic flag bits.
        assert t["flags"] == int(l4.flags) & 0xFF
        assert t["win"] == l4.window
        assert t["doff"] == l4.dataofs
        assert t["csum"] == l4.chksum
        assert t["urg"] == l4.urgptr
        assert t["opts"] == _tcp_opts(l4)
    elif l4 is not None and isinstance(l4, UDP):
        u = j["udp"]
        assert (u["sport"], u["dport"], u["len"], u["csum"]) == (
            l4.sport, l4.dport, l4.len, l4.chksum)


def compare_all(path, pkts, frames=None):
    """Run the CLI and compare every packet with scapy. Returns CLI output."""
    jp, flows, summ = run(path)
    frames = frames or [raw(p) for p in pkts]
    assert len(jp) == len(frames)
    for j, b in zip(jp, frames):
        assert j["err"] == "ok", (j["n"], j["err"])
        compare_with_scapy(j, b)
    return jp, flows, summ


# ---- tshark as a second reference --------------------------------------

TSHARK_ARGS = ["-o", "tcp.relative_sequence_numbers:FALSE",
               "-o", "tcp.analyze_sequence_numbers:TRUE"]

# netparse event name -> tshark display filter
TSHARK_EVENTS = {
    "retransmission": "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"
                      " || tcp.analysis.spurious_retransmission",
    "out-of-order": "tcp.analysis.out_of_order",
    "dup-ack": "tcp.analysis.duplicate_ack",
    "zero-window": "tcp.analysis.zero_window",
    "keep-alive": "tcp.analysis.keep_alive",
    "gap": "tcp.analysis.lost_segment",
}


def tshark_frames(path, dfilter):
    out = subprocess.run([TSHARK, "-n", "-r", str(path), *TSHARK_ARGS, "-Y", dfilter,
                          "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return {int(x) for x in out.stdout.split()}


def tshark_fields(path, fields):
    args = [TSHARK, "-n", "-r", str(path), *TSHARK_ARGS, "-T", "fields",
            "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in fields:
        args += ["-e", f]
    out = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    rows = []
    for line in out.stdout.splitlines():
        rows.append(dict(zip(fields, line.split("|"))))
    return rows


def our_events(jp, name):
    return {j["n"] for j in jp if name in j["events"]}


def check_events_vs_tshark(path, jp, names=TSHARK_EVENTS):
    """Per-packet agreement on TCP analysis events with tshark."""
    if not TSHARK:
        return
    for name in names:
        theirs = tshark_frames(path, TSHARK_EVENTS[name])
        ours = our_events(jp, name)
        assert ours == theirs, f"{name}: netparse {sorted(ours)} tshark {sorted(theirs)}"


def flow_by_ports(flows, port):
    for f in flows:
        if f["a"].endswith(f":{port}") or f["b"].endswith(f":{port}"):
            return f
    raise AssertionError(f"no flow on port {port}")
