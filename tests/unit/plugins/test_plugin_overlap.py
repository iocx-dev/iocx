from iocx.engine import Engine

def test_plugin_overlap_suppression(tmp_path, monkeypatch):
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "overlap_plugin.py"
    plugin_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="overlap",
        name="Overlap",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text, ctx):
        return [
            Detection("A", 0, 10, "plugin.test"),
            Detection("B", 5, 15, "plugin.test")
        ]
""")

    monkeypatch.setenv("HOME", str(tmp_path))

    engine = Engine()
    result = engine.extract_from_text("dummy text")

    # Only the first detection survives
    assert result["iocs"]["plugin.test"] == ["A"]
