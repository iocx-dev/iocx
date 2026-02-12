import json
import subprocess
import pytest


@pytest.mark.integration
def test_cli_with_text_input():
    text = "Visit http://example.com and example.org"

    result = subprocess.run(
        ["malx-ioc-extractor", text],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)

    assert "iocs" in data
    assert "urls" in data["iocs"]
    assert "domains" in data["iocs"]

    assert "http://example.com" in data["iocs"]["urls"]
    assert "example.org" in data["iocs"]["domains"]
