# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.engine import Engine
from iocx.models import Detection

def test_enrichment_applied_to_merged_iocs():
    engine = Engine()

    # Simulate raw detections
    raw = {
        "registry.keys": [
            Detection("HKLM\\Software\\BadStuff", 0, 10, "registry.keys"),
            Detection("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BadApp", 20, 40, "registry.keys"),
        ]
    }

    merged = engine._post_process(raw)

    # IOC buckets should be strings
    assert merged["registry.keys"] == [
        "HKLM\\Software\\BadStuff",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BadApp",
    ]

    # Plugin context must exist
    assert engine._plugin_context is not None

    enrichment = engine._plugin_context.metadata

    # If no enrichers are installed, skip enrichment assertions
    if not engine._plugin_registry.enrichers:
        pytest.skip("No enrichers installed; skipping enrichment assertions")

    # Otherwise, enrichment must contain metadata for registry keys
    assert "registry.keys" in enrichment
    assert len(enrichment["registry.keys"]) == 2

    for entry in enrichment["registry.keys"]:
        assert "value" in entry
        assert "score" in entry
        assert "reasons" in entry
        assert "flags" in entry
