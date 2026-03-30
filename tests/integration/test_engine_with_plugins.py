import types
import pytest
from pathlib import Path

from iocx.engine import Engine, EngineConfig
from iocx.plugins.metadata import PluginMetadata


# ---------------------------------------------------------
# Fake entrypoint detector plugin
# ---------------------------------------------------------

class FakeEntrypointPlugin:
    metadata = PluginMetadata(
        id="entry.detector",
        name="Entry Detector",
        version="1.0",
        description="Fake entrypoint detector",
        author="Tester",
        iocx_min_version="0.4.0",
        capabilities=["detector"],
    )

    def detect(self, text, context):
        return [{"type": "domains", "value": "domain.com"}]


@pytest.mark.integration
def test_engine_end_to_end_with_plugins(monkeypatch, tmp_path):

    # -----------------------------------------------------
    # 1. Fake entrypoint plugin
    # -----------------------------------------------------
    class FakeDetectorEntryPoint:
        name = "entry.detector"

        def load(self):
            return FakeEntrypointPlugin

    monkeypatch.setattr(
        "iocx.plugins.loader.importlib.metadata.entry_points",
        lambda: types.SimpleNamespace(
            select=lambda group: [FakeDetectorEntryPoint()]
        )
    )

    # -----------------------------------------------------
    # 2. Create a local plugin in ~/.iocx/plugins
    # -----------------------------------------------------
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "local_plugin.py"
    plugin_file.write_text(
        "from iocx.plugins.metadata import PluginMetadata\n"
        "class Plugin:\n"
        " metadata = PluginMetadata(\n"
        " id='local.detector',\n"
        " name='Local Detector',\n"
        " author='Tester',\n"
        " iocx_min_version='0.4.0',\n"
        " version='1.0',\n"
        " description='Local test plugin',\n"
        " capabilities=['detector']\n"
        " )\n"
        " def detect(self, text, context):\n"
        "     return [{'type': 'domains', 'value': 'test.com'}]\n"
    )

    # IMPORTANT: patch Path.home INSIDE the loader module
    monkeypatch.setattr("iocx.plugins.loader.Path.home", lambda: tmp_path)

    # -----------------------------------------------------
    # 3. Create a sample input file
    # -----------------------------------------------------
    input_file = tmp_path / "sample.txt"
    input_file.write_text("This is a test file with real domain indicators: domain.com AND test.com")

    # -----------------------------------------------------
    # 4. Run the full engine
    # -----------------------------------------------------
    engine = Engine(config=EngineConfig(enable_local_plugins=True))
    registry = engine._plugin_registry

    result = engine.extract(input_file)

    # -----------------------------------------------------
    # 5. Assertions
    # -----------------------------------------------------

    # Both detectors should be loaded
    detector_ids = {p.metadata.id for p in registry.detectors}
    assert "entry.detector" in detector_ids
    assert "local.detector" in detector_ids

    # Engine should return IOCs result structure
    assert "iocs" in result
    assert "metadata" in result

    # Both detectors should have contributed
    values = result["iocs"]["domains"]
    assert "domain.com" in values
    assert "test.com" in values
