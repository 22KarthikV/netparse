# SPDX-License-Identifier: MIT
"""Live AF_PACKET capture on loopback. Needs CAP_NET_RAW; skipped otherwise."""
import json
import signal
import socket
import subprocess
import threading
import time

import pytest
from npharness import BIN


def _can_capture():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.close()
        return True
    except (PermissionError, OSError, AttributeError):
        return False


pytestmark = pytest.mark.skipif(not _can_capture(), reason="needs CAP_NET_RAW (root)")


def test_live_loopback_tcp():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        while True:
            d = c.recv(65536)
            if not d:
                break
        c.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    proc = subprocess.Popen([BIN, "-j", "-i", "lo"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    time.sleep(0.7)  # ring setup
    cli = socket.create_connection(("127.0.0.1", port))
    for _ in range(20):
        cli.sendall(b"L" * 1000)
    cli.close()
    th.join(5)
    srv.close()
    time.sleep(0.5)
    proc.send_signal(signal.SIGINT)
    out, err = proc.communicate(timeout=10)
    assert proc.returncode == 0, err
    assert "AddressSanitizer" not in err and "runtime error" not in err
    recs = [json.loads(line) for line in out.splitlines()]
    flows = [r for r in recs if r["type"] == "flow" and
             (r["a"].endswith(f":{port}") or r["b"].endswith(f":{port}"))]
    assert len(flows) == 1
    f = flows[0]
    assert f["b"] == f"127.0.0.1:{port}"          # client initiated
    a = f["a_to_b"]
    assert a["syn"] == 1 and a["fin"] == 1
    assert a["payload_bytes"] == 20000
    assert a["retransmits"] == 0                   # loopback duplicates filtered
    pk = [r for r in recs if r["type"] == "pkt" and "tcp" in r["layers"] and
          port in (r["tcp"]["sport"], r["tcp"]["dport"])]
    assert all(r["err"] == "ok" for r in pk)
