import json
import subprocess
from pathlib import Path
import pytest

@pytest.mark.integration
def test_cli_with_rsrc_embedded_iocs():
    fixture = Path("tests/fixtures/pe_with_rsrc_iocs.exe")
    assert fixture.exists(), "Missing .rsrc PE fixture"

    result = subprocess.run(
        ["iocx", str(fixture)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)
    iocs = data["iocs"]

    # URL
    assert "http://malx-rsrc.example" in iocs["urls"]

    # Email
    assert "rsrc-attacker@example.com" in iocs["emails"]

    # Filepath
    assert r"c:\windows\system32\rsrc.dll" in iocs["filepaths"]

    # IP
    assert "66.77.88.99" in iocs["ips"]

    # Base64
    assert "YmFzZTY0LXJzcmMtc3RyaW5n" in iocs["base64"]
