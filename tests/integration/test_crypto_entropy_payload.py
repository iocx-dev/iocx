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
    heuristics = result["analysis"]["heuristics"]

    # Extract only API-based heuristics (those that have a "function" field)
    api_funcs = {
        h["metadata"]["function"]
        for h in heuristics
        if "function" in h["metadata"]
    }

    # Expected MSVC CRT imports
    assert api_funcs == {"QueryPerformanceCounter", "IsDebuggerPresent"}

    # Extract structural anomaly reasons
    structural_reasons = {
        h["metadata"]["reason"]
        for h in heuristics
        if h["value"] == "pe_structure_anomaly"
    }

    # These anomalies are expected for this test binary
    assert structural_reasons == {
        "load_config_guard_cf_inconsistent", "load_config_cookie_invalid"
    }


@pytest.mark.integration
def test_crypto_entropy_payload_rich_header(crypto_payload_result):
    result = crypto_payload_result
    rh = result["analysis"]["extended"]
    rich = next(x for x in rh if x["value"] == "rich_header")

    md = rich["metadata"]
    assert "raw_data" in md
    assert isinstance(md["raw_data"], str)
    assert all(c in "0123456789abcdef" for c in md["raw_data"].lower())
