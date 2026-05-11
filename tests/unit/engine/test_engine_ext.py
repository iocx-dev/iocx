# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.engine import Engine
from iocx.models import Detection


@pytest.fixture
def engine():
    return Engine()

@pytest.fixture
def engine_tuple():
    e = Engine()
    # Replace plugin registry with our controlled test plugin
    e._plugin_registry.detectors = [TupleDetector()]
    return e

@pytest.fixture
def engine_enricher():
    e = Engine()
    # Replace enrichers with our failing plugin
    e._plugin_registry.enrichers = [FailingEnricher()]
    return e

@pytest.fixture
def engine_malformed():
    e = Engine()
    e._plugin_registry.detectors = [MalformedDetector()]
    return e


class TupleDetector:
    """Detector that returns 4‑tuple IOC items."""
    class metadata:
        id = "tuple-detector"

    def detect(self, text, ctx):
        # category → list of 4‑tuples
        return {
            "urls": [
                ("http://example.com", 0, 18, "urls")
            ]
        }

class FailingEnricher:
    """Enricher that always raises to hit the exception branch."""
    class metadata:
        id = "failing-enricher"

    def enrich(self, text, ctx):
        raise RuntimeError("boom")

class BadDetector:
    """Detector that returns malformed items to hit line 241."""
    def __call__(self, text):
        return [
            123, # malformed → triggers the continue branch (line 241)
            ("ok", 0, 2, "test"), # valid → ensures loop continues
        ]

def test_analyze_file_creates_detections_and_manages_depth_stack(engine):
    # Start with a known depth stack state
    engine.depth_stack = [0]

    # Stub out internal methods to avoid real file parsing
    engine._build_plugin_context = lambda path, _: {}
    engine.extract_from_file = lambda path: {
        "iocs": {
            "url": ["http://example.com"],
            "ip": ["1.2.3.4"],
        }
    }

    detections = engine.analyze_file("dummy.bin")

    # depth_stack should return to original state after recursion
    assert engine.depth_stack == [0]

    # Should produce two Detection objects
    assert len(detections) == 2

    # Validate categories and values
    categories = {d.category for d in detections}
    values = {d.value for d in detections}

    assert categories == {"url", "ip"}
    assert values == {"http://example.com", "1.2.3.4"}

    # start/end should be zero
    for d in detections:
        assert d.start == 0
        assert d.end == 0


def test_tuple_detector_branch(engine_tuple):
    result = engine_tuple._run_detectors("dummy", "http://example.com")

    # Ensure category exists
    assert "urls" in result

    items = result["urls"]
    assert len(items) == 1

    det = items[0]
    assert isinstance(det, Detection)

    # Ensure the tuple was converted correctly
    assert det.value == "http://example.com"
    assert det.start == 0
    assert det.end == 18
    assert det.category == "urls"


def test_enricher_exception_branch(engine_enricher, caplog):
    # Run any method that triggers the enricher pipeline
    # _run_enrichers is internal, but extract() calls it
    engine_enricher.extract("dummy text")

    # The exception branch logs a warning — assert it happened
    messages = " ".join(record.message for record in caplog.records)
    assert "failing-enricher" in messages
    assert "failed" in messages


def test_all_detectors_malformed_item_hits_continue(engine, monkeypatch):
    # Patch all_detectors() to return our bad detector
    monkeypatch.setitem(
        engine._run_detectors.__globals__,
        "all_detectors",
        lambda: {"bad": BadDetector()},
    )

    result = engine._run_detectors("dummy", "text")

    # Only the valid tuple should survive
    assert "bad" in result
    items = result["bad"]

    assert len(items) == 1
    assert isinstance(items[0], Detection)
    assert items[0].value == "ok"
