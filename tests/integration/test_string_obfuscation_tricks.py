# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import json
import subprocess
from pathlib import Path
import pytest


@pytest.fixture(scope="module")
def string_obfuscation_tricks_result():
    """Run IOCX on the string obfuscation tricks payload and return parsed JSON."""
    exe = Path("tests/contract/fixtures/layer3_adversarial/string_obfuscation_tricks.full.exe")
    proc = subprocess.run(
        ["iocx", str(exe), "-a", "full"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


@pytest.mark.integration
def test_string_obfuscation_iocs(string_obfuscation_tricks_result):
    result = string_obfuscation_tricks_result
    urls = result["iocs"]["urls"]
    assert "http://literal-ioc.test/path" in urls
    assert "http://example.com/pathmoc.elpmaxh" in urls
    assert "http://bad.test" in urls

    assert result["iocs"]["ips"] == ["198.51.100.42"]


@pytest.mark.integration
def test_string_obfuscation_sections(string_obfuscation_tricks_result):
    result = string_obfuscation_tricks_result
    sections = {s["name"]: s for s in result["analysis"]["sections"]}

    assert ".obfs" in sections
    assert sections[".obfs"]["entropy"] < 1.0
    assert sections[".obfs"]["raw_size"] == 512


@pytest.mark.integration
def test_string_obfuscation_heuristics(string_obfuscation_tricks_result):
    result = string_obfuscation_tricks_result
    heur = {h["metadata"]["function"] for h in result["analysis"]["heuristics"]}

    assert "OutputDebugStringA" in heur
    assert "IsDebuggerPresent" in heur
    assert "QueryPerformanceCounter" in heur


@pytest.mark.integration
def test_string_obfuscation_rich_header(string_obfuscation_tricks_result):
    result = string_obfuscation_tricks_result
    rh = result["analysis"]["extended"]
    rich = next(x for x in rh if x["value"] == "rich_header")

    md = rich["metadata"]
    assert "raw_data" in md
    assert isinstance(md["raw_data"], str)
    assert all(c in "0123456789abcdef" for c in md["raw_data"].lower())
