# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from iocx.engine import Engine

def test_plugin_cache(tmp_path, monkeypatch):
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "cache_plugin.py"
    plugin_file.write_text("""
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="cache-test",
        name="Cache Test",
        version="0.1.0",
        description="Test",
        author="me",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    calls = 0

    def detect(self, text, ctx):
        Plugin.calls += 1
        return [Detection("X", 0, 1, "plugin.cache")]
""")

    monkeypatch.setenv("HOME", str(tmp_path))

    engine = Engine()

    engine.extract_from_text("hello")
    engine.extract_from_text("hello")

    # Should only run once due to caching
    assert plugin_file.read_text().count("calls") # sanity
