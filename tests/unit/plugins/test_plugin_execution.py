from pathlib import Path
from iocx.engine import Engine, EngineConfig

def test_plugin_detector_runs(tmp_path, monkeypatch):
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "detector_plugin.py"
    plugin_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection, PluginContext

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="plugin-test",
        name="Plugin Test",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text, ctx):
        return [Detection("X", 100, 101, "plugin.test")]
""")

    monkeypatch.setenv("HOME", str(tmp_path))

    engine = Engine(config=EngineConfig(enable_local_plugins=True))
    result = engine.extract_from_text("hello")

    assert result["iocs"]["plugin.test"] == ["X"]
