import subprocess
import sys
from pathlib import Path
import json


def run_cli(*args, input=None):
    """Helper to run the CLI and return stdout/stderr."""
    result = subprocess.run(
        [sys.executable, "-m", "iocx.cli.main", *args],
        input=input,
        capture_output=True,
        text=True
    )
    return result


def test_cli_extracts_from_file(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com")

    result = run_cli(str(sample))
    assert result.returncode == 0
    assert "example.com" in result.stdout


def test_cli_extracts_from_stdin():
    result = run_cli("-", input="http://example.com")
    assert result.returncode == 0
    assert "example.com" in result.stdout


def test_cli_compact_flag(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com")

    result = run_cli(str(sample), "--compact")
    assert result.returncode == 0
    # Pretty JSON should contain newlines and indentation
    assert "\n  \"" not in result.stdout


def test_cli_list_detectors():
    result = run_cli("--list-detectors")
    assert result.returncode == 0
    # Should list at least one known detector
    assert "urls" in result.stdout.lower()


def test_cli_version():
    result = run_cli("--version")
    assert result.returncode == 0
    # Version should look like "0.1.0" or similar
    assert result.stdout.strip()[0].isdigit()


def test_cli_help():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()
    assert "input" in result.stdout.lower()


def test_cli_no_cache_flag(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com")

    result = run_cli(str(sample), "--no-cache")
    assert result.returncode == 0
    assert "example.com" in result.stdout
