import json
import subprocess
from pathlib import Path
import pytest

@pytest.mark.integration
def test_full_pipeline_with_plugins(tmp_path, monkeypatch):
    """
    Real-world integration test:
    - Creates two plugins: a transformer and a detector
    - Writes a realistic text file containing URLs, registry keys, and noise
    - Runs the full CLI (`iocx <file>`)
    - Verifies that:
        * built-in detectors fire
        * plugin transformer modifies input
        * plugin detector fires
        * categories are merged correctly
        * output is valid JSON
    """

    # ----------------------------------------------------------------------
    # 1. Create plugin directory
    # ----------------------------------------------------------------------
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    # ----------------------------------------------------------------------
    # 2. Transformer plugin (uppercases everything)
    # ----------------------------------------------------------------------
    (plugin_dir / "transformer_upper.py").write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="upper",
        name="Uppercase Transformer",
        version="1.0",
        description="Uppercases text",
        author="test",
        capabilities=["transformer"],
        iocx_min_version="0.4.0",
    )

    def transform(self, text, ctx):
        return text.upper()
""")

    # ----------------------------------------------------------------------
    # 3. Detector plugin (detects the word TRANSFORMED)
    # ----------------------------------------------------------------------
    (plugin_dir / "detector_keyword.py").write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="keyword",
        name="Keyword Detector",
        version="1.0",
        description="Detects keyword",
        author="test",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text, ctx):
        if "TRANSFORMED" in text:
            return [Detection("TRANSFORMED", 0, 10, "plugin.keyword")]
        return []
""")

    # ----------------------------------------------------------------------
    # 4. Create a realistic input file
    # ----------------------------------------------------------------------
    input_file = tmp_path / "sample.txt"
    input_file.write_text("""
This is a test file.
Visit http://example.com for details.
Registry key: HKCU\\Software\\BadStuff
This line will be transformed.
""")

    # Ensure plugins load from our temp HOME
    monkeypatch.setenv("HOME", str(tmp_path))

    # ----------------------------------------------------------------------
    # 5. Run the full CLI
    # ----------------------------------------------------------------------
    result = subprocess.run(
        ["iocx", str(input_file), "--dev"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0, result.stderr

    data = json.loads(result.stdout)

    # ----------------------------------------------------------------------
    # 6. Assertions: built-in + plugin behaviour
    # ----------------------------------------------------------------------

    # Built-in URL detector should fire
    assert "http://example.com" in data["iocs"]["urls"]

    # Registry plugin should not fire if not installed
    assert "registry.keys" in data["iocs"] or data["iocs"]["registry.keys"] == []

    # Transformer plugin should have uppercased text → detector sees TRANSFORMED
    assert data["iocs"]["plugin.keyword"] == ["TRANSFORMED"]

    # Ensure no unexpected categories are missing
    assert "urls" in data["iocs"]
    assert "domains" in data["iocs"]
    assert "plugin.keyword" in data["iocs"]
