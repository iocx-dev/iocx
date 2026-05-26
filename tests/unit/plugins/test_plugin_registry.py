# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from iocx.plugins.registry import PluginRegistry
import pytest


def test_register_all_capabilities():
    registry = PluginRegistry()

    class FakeCaps:
        capabilities = ["detector", "enricher", "transformer"]

    class FakePlugin:
        metadata = FakeCaps()

    plugin = FakePlugin()
    registry.register(plugin)

    assert registry.detectors == [plugin]
    assert registry.enrichers == [plugin]
    assert registry.transformers == [plugin]
