# SPDX-License-Identifier: MIT
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import npharness  # noqa: E402


def pytest_report_header(config):
    return [f"netparse binary: {npharness.BIN}",
            f"tshark reference: {npharness.TSHARK or 'not installed (scapy only)'}"]


@pytest.fixture(scope="session", autouse=True)
def _binary_exists():
    if not os.path.exists(npharness.BIN):
        pytest.exit(f"{npharness.BIN} not built; run make first", returncode=2)
