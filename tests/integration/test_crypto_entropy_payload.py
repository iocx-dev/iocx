# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import json
import subprocess
from pathlib import Path
import pytest


@pytest.fixture(scope="module")
def crypto_payload_result():
    """Run IOCX on the crypto entropy payload and return parsed JSON."""
    exe = Path("tests/contract/fixtures/layer3_adversarial/crypto_entropy_payload.full.exe")
    proc = subprocess.run(
        ["iocx", str(exe), "-a", "full"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


@pytest.mark.integration
def test_crypto_entropy_payload_iocs(crypto_payload_result):
    result = crypto_payload_result
    assert result["iocs"]["urls"] == []
    assert result["iocs"]["domains"] == []
    assert result["iocs"]["ips"] == []
    assert result["iocs"]["hashes"] == []
    assert result["iocs"]["emails"] == []
    assert result["iocs"]["filepaths"] == []
    assert result["iocs"]["crypto.btc"] == []
    assert result["iocs"]["crypto.eth"] == []


@pytest.mark.integration
def test_crypto_entropy_payload_sections(crypto_payload_result):
    result = crypto_payload_result
    sections = {s["name"]: s for s in result["analysis"]["sections"]}

    assert ".crypt" in sections
    assert sections[".crypt"]["entropy"] >= 5.5
    assert sections[".crypt"]["raw_size"] == 512
    assert sections[".crypt"]["virtual_size"] == 512


@pytest.mark.integration
def test_crypto_entropy_payload_heuristics(crypto_payload_result):
    result = crypto_payload_result
    heur = {h["metadata"]["function"] for h in result["analysis"]["heuristics"]}

    # These are expected MSVC CRT imports
    assert "QueryPerformanceCounter" in heur
    assert "IsDebuggerPresent" in heur

    # No other heuristics should fire
    assert heur <= {"QueryPerformanceCounter", "IsDebuggerPresent"}


@pytest.mark.integration
def test_crypto_entropy_payload_rich_header(crypto_payload_result):
    result = crypto_payload_result
    rh = result["analysis"]["extended"]
    rich = next(x for x in rh if x["value"] == "rich_header")

    md = rich["metadata"]
    assert "raw_data" in md
    assert isinstance(md["raw_data"], str)
    assert all(c in "0123456789abcdef" for c in md["raw_data"].lower())
