import json
import subprocess
import pytest

@pytest.mark.integration
def test_cli_with_text_file(tmp_path):
    file = tmp_path / "ioc_test.txt"
    file.write_text("Check https://malx.io and test.net")

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
