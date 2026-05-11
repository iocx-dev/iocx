# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import types
import importlib.metadata
import importlib.util
from pathlib import Path

import pytest

from iocx.plugins.loader import PluginLoader


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

class MetaDetector:
    capabilities = {"detector"}


class MetaInvalid:
    capabilities = set()


class ValidDetectorPlugin:
    metadata = MetaDetector()

    def detect(self):
        pass


class InvalidPlugin_NoMethods:
    metadata = MetaDetector()


class InvalidPlugin_NoMetadata:
    def detect(self):
        pass


# ---------------------------------------------------------
# _is_valid_plugin
# ---------------------------------------------------------

def test_is_valid_plugin_accepts_valid_plugin():
    loader = PluginLoader()
    plugin = ValidDetectorPlugin()
    assert loader._is_valid_plugin(plugin) is True


def test_is_valid_plugin_rejects_missing_methods():
    loader = PluginLoader()
    plugin = InvalidPlugin_NoMethods()
    assert loader._is_valid_plugin(plugin) is False


def test_is_valid_plugin_rejects_missing_metadata():
    loader = PluginLoader()
    plugin = InvalidPlugin_NoMetadata()
    assert loader._is_valid_plugin(plugin) is False


# ---------------------------------------------------------
# Entrypoint plugin loading
# ---------------------------------------------------------

def test_load_entrypoint_plugins_valid(monkeypatch):
    loader = PluginLoader()

    class FakeEntryPoint:
        name = "valid-plugin"

        def load(self):
            return ValidDetectorPlugin

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda: types.SimpleNamespace(select=lambda group: [FakeEntryPoint()]),
    )

    loader._load_entrypoint_plugins()

    assert len(loader.registry.detectors) == 1
    assert isinstance(loader.registry.detectors[0], ValidDetectorPlugin)


def test_load_entrypoint_plugins_invalid(monkeypatch, caplog):
    loader = PluginLoader()

    class FakeEntryPoint:
        name = "invalid-plugin"

        def load(self):
            return InvalidPlugin_NoMethods

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda: types.SimpleNamespace(select=lambda group: [FakeEntryPoint()]),
    )

    loader._load_entrypoint_plugins()

    assert len(loader.registry.detectors) == 0
    assert "not a valid IOCX plugin" in caplog.text


def test_load_entrypoint_plugins_load_failure(monkeypatch, caplog):
    loader = PluginLoader()

    class FakeEntryPoint:
        name = "broken-plugin"

        def load(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda: types.SimpleNamespace(select=lambda group: [FakeEntryPoint()]),
    )

    loader._load_entrypoint_plugins()

    assert len(loader.registry.detectors) == 0
    assert "Failed to load plugin 'broken-plugin'" in caplog.text


# ---------------------------------------------------------
# Local plugin loading
# ---------------------------------------------------------

def test_load_local_plugins_valid(monkeypatch, tmp_path):
    loader = PluginLoader()

    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "test_plugin.py"
    plugin_file.write_text(
        "from iocx.plugins.metadata import PluginMetadata\n"
        "class Plugin:\n"
        " metadata = PluginMetadata(\n"
        " id='test.plugin',\n"
        " name='Test Plugin',\n"
        " author='Tester', \n"
        " iocx_min_version='0.4.0', \n"
        " version='1.0.0',\n"
        " description='Test plugin',\n"
        " capabilities=['detector']\n"
        " )\n"
        " def detect(self):\n"
        "  pass\n"
    )

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    loader._load_local_plugins()

    assert len(loader.registry.detectors) == 1
    plugin = loader.registry.detectors[0]
    assert hasattr(plugin, "detect")
    assert "detector" in plugin.metadata.capabilities


def test_load_local_plugins_missing_plugin_class(monkeypatch, tmp_path, caplog):
    loader = PluginLoader()

    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "bad_plugin.py"
    plugin_file.write_text("x = 1\n")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    loader._load_local_plugins()

    assert len(loader.registry.detectors) == 0
    assert "has no Plugin class" in caplog.text


def test_load_local_plugins_invalid_plugin(monkeypatch, tmp_path, caplog):
    loader = PluginLoader()

    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "invalid_plugin.py"
    plugin_file.write_text(
        "class Meta:\n"
        " capabilities = {'detector'}\n"
        "\n"
        "class Plugin:\n"
        " metadata = Meta()\n"
        " # no detect/transform/enrich\n"
    )

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    loader._load_local_plugins()

    assert len(loader.registry.detectors) == 0
    assert "is not a valid IOCX plugin" in caplog.text


def test_load_local_plugins_bad_spec(monkeypatch, tmp_path, caplog):
    loader = PluginLoader()

    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    plugin_file = plugin_dir / "broken.py"
    plugin_file.write_text("class Plugin: pass\n")

    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    loader._load_local_plugins()

    assert "Could not load spec for local plugin" in caplog.text
    assert len(loader.registry.detectors) == 0


def test_load_local_plugins_error_block(monkeypatch, tmp_path, caplog):
    loader = PluginLoader()

    # Create ~/.iocx/plugins directory
    plugin_dir = tmp_path / ".iocx" / "plugins"
    plugin_dir.mkdir(parents=True)

    # Create a dummy plugin file
    plugin_file = plugin_dir / "broken_plugin.py"
    plugin_file.write_text("class Plugin: pass")

    # Patch Path.home() to point to tmp_path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    # Create a real ModuleSpec, but override its loader
    real_spec = importlib.util.spec_from_file_location(
        "broken_plugin", plugin_file
    )

    class FakeLoader:
        def create_module(self, spec):
            return None # required

        def exec_module(self, module):
            raise RuntimeError("simulated failure")

    real_spec.loader = FakeLoader()

    # Patch spec_from_file_location to return our modified spec
    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda *args, **kwargs: real_spec
    )

    caplog.set_level("ERROR")

    loader._load_local_plugins()

    # Assert: our simulated failure was logged
    assert "simulated failure" in caplog.text
    assert "Failed to load local plugin" in caplog.text

    # Assert: loader continued without crashing
    assert len(loader.registry.detectors) == 0
    assert len(loader.registry.enrichers) == 0
    assert len(loader.registry.transformers) == 0


def test_load_entrypoint_plugins_exception(monkeypatch, caplog):
    loader = PluginLoader()

    # Force entry_points() to raise an exception
    def fake_entry_points():
        raise RuntimeError("boom")

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)

    caplog.set_level("WARNING")

    loader._load_entrypoint_plugins()

    # Assert the warning was logged
    assert "[iocx] Failed to enumerate entrypoints: boom" in caplog.text

    # Assert no plugins were registered
    assert loader.registry.detectors == []
    assert loader.registry.enrichers == []
    assert loader.registry.transformers == []


def test_load_local_plugins_returns_when_directory_missing(monkeypatch):
    loader = PluginLoader()

    # Patch Path.home() to point to a fake directory that does NOT contain .iocx/plugins
    fake_home = Path("/nonexistent/home/dir")
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    # Ensure the directory truly does not exist
    assert not (fake_home / ".iocx" / "plugins").exists()

    # Call the method — it should immediately return without errors
    loader._load_local_plugins()

    # Assert: nothing was registered
    assert loader.registry.detectors == []
    assert loader.registry.enrichers == []
    assert loader.registry.transformers == []


def test_plugin_registry_register_no_metadata():
    from iocx.plugins.registry import PluginRegistry
    registry = PluginRegistry()

    class PluginWithoutMetadata:
        pass

    plugin = PluginWithoutMetadata()

    # Should hit: if caps is None: return
    registry.register(plugin)

    # Nothing should be added
    assert registry.detectors == []
    assert registry.enrichers == []
    assert registry.transformers == []
