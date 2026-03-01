import subprocess
import sys
from pathlib import Path

def test_cli_runs(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com")

    result = subprocess.run(
        [sys.executable, "-m", "iocx.cli.main", str(sample)],
        capture_output=True,
        text=True
    )

    assert "example.com" in result.stdout
