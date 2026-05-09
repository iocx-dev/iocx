# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import json
import subprocess
import pytest
from pathlib import Path

@pytest.mark.integration
@pytest.mark.skip(reason="Skipping until pe is restored")
def test_cli_with_generated_pe_with_iocs():
    fixture = Path("tests/fixtures/pe_with_iocs.exe")

    result = subprocess.run(
        ["iocx", str(fixture)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)
    iocs = data["iocs"]

    assert "https://c2.example.com/api" in iocs["urls"]
    assert "evil-domain.net" in iocs["domains"]
    assert "attacker@example.org" in iocs["emails"]
    assert r"c:\users\victim\documents\secrets.txt" in iocs["filepaths"]
    assert r"\\fileserver01\malware\dropper.exe" in iocs["filepaths"]
    assert r"\\10.0.0.42\c$\windows\temp\evil.ps1" in iocs["filepaths"]
    assert "192.168.56.101" in iocs["ips"]
    assert (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        in iocs["hashes"]
    )
    assert "aGVsbG8gd29ybGQ= (decoded: hello world)" in iocs["base64"]
