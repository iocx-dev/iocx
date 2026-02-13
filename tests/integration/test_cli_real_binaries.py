import json
import subprocess
from pathlib import Path
import pytest

@pytest.mark.integration
def test_cli_with_real_go_binary(tmp_path):
    go_bin = tmp_path / "go_test_bin"

    # Build a tiny Go program
    go_source = tmp_path / "main.go"
    go_source.write_text('package main\nfunc main() {}\n')
    subprocess.run(
        ["go", "build", "-o", str(go_bin), str(go_source)],
        check=True
    )

    assert go_bin.exists(), "Go binary must exist for this test"

    result = subprocess.run(
        ["iocx", str(go_bin)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)

    assert "iocs" in data
    assert "metadata" in data
    assert "filepaths" in data["iocs"]
    assert isinstance(data["iocs"]["filepaths"], list)

    # PE metadata should be present or empty depending on platform
    assert isinstance(data["metadata"], dict)


@pytest.mark.integration
def test_cli_with_real_python_binary(tmp_path):
    py_bin = tmp_path / "py_test_bin"

    # Generate a Python executable
    py_bin.write_text("#!/usr/bin/env python3\nprint('hello')")
    py_bin.chmod(0o755)

    assert py_bin.exists(), "Python binary must exist for this test"

    result = subprocess.run(
        ["iocx", str(py_bin)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    data = json.loads(result.stdout)

    assert "iocs" in data
    assert "metadata" in data
    assert "filepaths" in data["iocs"]
    assert isinstance(data["iocs"]["filepaths"], list)

