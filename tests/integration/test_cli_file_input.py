import json
import subprocess
import pytest

@pytest.mark.integration
def test_cli_with_text_file_simple(tmp_path):
    file = tmp_path / "ioc_test.txt"
    file.write_text(r"Check https://malx.io and test.net c:\users\bob\file.txt test@test.com")

    result = subprocess.run(
        ["iocx", str(file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)

    assert "iocs" in data
    assert "urls" in data["iocs"]
    assert "domains" in data["iocs"]

    assert "https://malx.io" in data["iocs"]["urls"]
    assert "test.net" in data["iocs"]["domains"]
    assert r"c:\users\bob\file.txt" in data["iocs"]["filepaths"]

@pytest.mark.integration
def test_cli_with_all_iocs(tmp_path):
    file = tmp_path / "all_iocs.txt"

    # This line includes:
    # - URL
    # - Domain
    # - Email
    # - Filepath
    # - IP address
    # - Hash (SHA256)
    # - Base64 ("hello world")
    file.write_text(
        r"""
        Visit https://example.com and contact admin@example.com.
        The server at 8.8.8.8 dropped this file: C:\temp\malware.exe
        Domain to watch: evil.net
        Hash: d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
        Encoded: aGVsbG8gd29ybGQ=
        """
    )

    result = subprocess.run(
        ["iocx", str(file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)

    iocs = data["iocs"]

    # URL
    assert "https://example.com" in iocs["urls"]

    # Domain
    assert "evil.net" in iocs["domains"]

    # Email
    assert "admin@example.com" in iocs["emails"]

    # Filepath
    assert r"C:\temp\malware.exe" in iocs["filepaths"]

    # IP
    assert "8.8.8.8" in iocs["ips"]

    # Hash
    assert (
        "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
        in iocs["hashes"]
    )

    # Base64
    assert "aGVsbG8gd29ybGQ=" in iocs["base64"]

@pytest.mark.integration
def test_cli_with_unc_network_paths(tmp_path):
    file = tmp_path / "all_iocs_unc.txt"

    file.write_text(
        r"""
        Connect to \\fileserver01\malware\dropper.exe immediately.
        Visit https://example.org or contact ops@example.org.
        Suspicious domain: badhost.net
        Local file: C:\Users\Bob\Desktop\loot.txt
        IP seen: 10.0.0.42
        SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        Encoded payload: aGVsbG8gd29ybGQ=
        """
    )

    result = subprocess.run(
        ["iocx", str(file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)
    iocs = data["iocs"]

    # UNC network share path
    assert r"\\fileserver01\malware\dropper.exe" in iocs["filepaths"]

    # URL
    assert "https://example.org" in iocs["urls"]

    # Domain
    assert "badhost.net" in iocs["domains"]

    # Email
    assert "ops@example.org" in iocs["emails"]

    # Local filepath
    assert r"C:\Users\Bob\Desktop\loot.txt" in iocs["filepaths"]

    # IP
    assert "10.0.0.42" in iocs["ips"]

    # Hash
    assert (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        in iocs["hashes"]
    )

    # Base64
    assert "aGVsbG8gd29ybGQ=" in iocs["base64"]

@pytest.mark.integration
def test_empty_file(tmp_path):
    file = tmp_path / "empty.txt"
    file.write_text("")

    result = subprocess.run(["iocx", str(file)], capture_output=True, text=True)
    assert result.returncode == 0

    data = json.loads(result.stdout)
    for key in data["iocs"]:
        assert data["iocs"][key] == []

