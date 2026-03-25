from iocx.engine import Engine

def test_plugin_transformer_runs_first(tmp_path, monkeypatch):
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "transformer_plugin.py"
    plugin_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="transformer",
        name="Transformer",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["transformer"],
        iocx_min_version="0.4.0",
    )

    def transform(self, text, ctx):
        return "TRANSFORMED"
""")

    detector_file = plugin_dir / "detector_plugin.py"
    detector_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="detector",
        name="Detector",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text, ctx):
        if text == "TRANSFORMED":
            return [Detection("OK", 0, 2, "plugin.detector")]
        return []
""")

    monkeypatch.setenv("HOME", str(tmp_path))

    engine = Engine()
    result = engine.extract_from_text("ignored")

    assert result["iocs"]["plugin.detector"] == ["OK"]
