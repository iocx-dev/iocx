import os
from pathlib import Path
from iocx.plugins.loader import PluginLoader

def test_local_plugin_discovery(tmp_path, monkeypatch):
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "test_plugin.py"
    plugin_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="test-plugin",
        name="Test Plugin",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text, ctx):
        return []
""")

    monkeypatch.setenv("HOME", str(tmp_path))

    loader = PluginLoader(enable_local_plugins=True)
    registry = loader.load_all()

    assert any(p.metadata.id == "test-plugin" for p in registry.detectors)
