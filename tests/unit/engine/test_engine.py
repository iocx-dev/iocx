import os
import pytest

from iocx.engine import Engine, EngineConfig, FileType, EngineCache
from iocx.models import Detection

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def make_det(value, start=0, end=None, category="urls"):
    end = end if end is not None else start + len(value)
    return Detection(value=value, start=start, end=end, category=category)


@pytest.fixture
def mock_detectors(monkeypatch):
    """
    Mock all_detectors() so that:
    - ips → one IP detection
    - urls → two URL detections
    - hashes → empty
    - everything else → empty
    """
    def fake_all_detectors():
        return {
            "ips": lambda text: [make_det("1.2.3.4", 0, 7, "ips")],
            "urls": lambda text: [
                make_det("http://a", 10, 18, "urls"),
                make_det("http://b", 20, 28, "urls"),
            ],
            "hashes": lambda text: [],
            "emails": lambda text: [],
            "filepaths": lambda text: [],
            "base64": lambda text: [],
            "domains": lambda text: [],
        }

    monkeypatch.setattr("iocx.engine.all_detectors", fake_all_detectors)
    return fake_all_detectors()

# ------------------------------------------------------------
# context initialisation
# ------------------------------------------------------------

def test_plugin_context_initialisation():

    engine = Engine()

    # Run extraction on simple text input
    engine.extract("hello world")

    ctx = engine.plugin_context

    # Context object exists
    assert ctx is not None

    # Raw text is preserved
    assert ctx.raw_text == "hello world"

    # <text> inputs should not have a file_path
    assert ctx.file_path is None

    # Detections always initialised as a dict
    assert isinstance(ctx.detections, dict)

    # All metadata values must be lists (empty before enrichment)
    for key, value in ctx.metadata.items():
        assert isinstance(value, list), f"metadata[{key}] must be a list"

    # Logger must exist
    assert hasattr(ctx, "logger")
    assert ctx.logger is not None

# ------------------------------------------------------------
# cache clearing
# ------------------------------------------------------------

def test_context_clear():
    cache = EngineCache()

    # Populate fields
    cache.pe_metadata["sample"] = {"arch": "x86"}
    cache.strings["sample"] = ["hello", "world"]
    cache.detections["sample"] = {"urls": [Detection("http://x", 0, 10, "urls")]}

    # Sanity check: fields are non‑empty before clear()
    assert cache.pe_metadata
    assert cache.strings
    assert cache.detections

    # Call the method under test
    cache.clear()

    # All fields should now be empty
    assert cache.pe_metadata == {}
    assert cache.strings == {}
    assert cache.detections == {}

# ------------------------------------------------------------
# extract() routing
# ------------------------------------------------------------

def test_extract_routes_to_text_when_not_file(monkeypatch, mock_detectors):
    engine = Engine()

    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)

    result = engine.extract("not_a_file")
    assert result["file"] is None
    assert "iocs" in result
    assert result["metadata"] == {}
    # from mock_detectors: ips + urls
    assert result["iocs"]["ips"] == ["1.2.3.4"]
    assert result["iocs"]["urls"] == ["http://a", "http://b"]


def test_extract_routes_to_file_when_exists(monkeypatch, mock_detectors):
    engine = Engine()

    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: True)
    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.TEXT)

    class FakeFile:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def read(self): return "hello world"

    monkeypatch.setattr("builtins.open", lambda *a, **k: FakeFile())

    result = engine.extract("file.txt")
    assert result["file"] == "file.txt"
    assert result["type"] == "text"
    assert result["iocs"]["ips"] == ["1.2.3.4"]
    assert result["iocs"]["urls"] == ["http://a", "http://b"]


# ------------------------------------------------------------
# PE pipeline
# ------------------------------------------------------------

def test_pipeline_pe(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"dummy")

    engine = Engine()

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.PE)

    monkeypatch.setattr("iocx.engine.parse_pe", lambda p: {
        "file_type": "PE",
        "imports": ["KERNEL32.dll"],
        "sections": [".text"],
        "resource_strings": ["RSRC_STRING"],
    })

    monkeypatch.setattr("iocx.engine.extract_strings", lambda p, min_length: ["STR1", "STR2"])

    result = engine.extract_from_file(str(path))

    assert result["type"] == "PE"
    assert result["file"] == str(path)
    assert result["metadata"]["file_type"] == "PE"
    # detectors are mocked, but we know urls/ips are present
    assert result["iocs"]["ips"] == ["1.2.3.4"]
    assert result["iocs"]["urls"] == ["http://a", "http://b"]


# ------------------------------------------------------------
# Text file pipeline
# ------------------------------------------------------------

def test_pipeline_text_file(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("hello world")

    engine = Engine()

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.TEXT)

    result = engine.extract_from_file(str(path))
    assert result["type"] == "text"
    assert result["file"] == str(path)
    assert result["iocs"]["ips"] == ["1.2.3.4"]
    assert result["iocs"]["urls"] == ["http://a", "http://b"]


def test_engine_extract_dispatches_to_file(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text("example.com")

    engine = Engine()
    result = engine.extract(str(p))

    assert result["file"] == str(p)
    assert result["type"] == "text"
    assert "iocs" in result


# ------------------------------------------------------------
# Unknown pipeline with fallback
# ------------------------------------------------------------

def test_pipeline_unknown_with_fallback(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"abc")

    engine = Engine()

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.UNKNOWN)
    monkeypatch.setattr("iocx.engine.extract_strings", lambda p, min_length: ["A", "B"])

    result = engine.extract_from_file(str(path))
    assert result["type"] == "unknown"
    assert result["file"] == str(path)
    assert result["iocs"]["ips"] == ["1.2.3.4"]
    assert result["iocs"]["urls"] == ["http://a", "http://b"]


def test_pipeline_unknown_no_fallback(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"abc")

    engine = Engine(EngineConfig(fallback_to_strings=False))

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.UNKNOWN)

    result = engine.extract_from_file(str(path))
    assert result["type"] == "unknown"
    assert result["file"] == str(path)
    assert result["iocs"] == {}


# ------------------------------------------------------------
# Caching behaviour
# ------------------------------------------------------------

def test_cache_used(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"abc")

    engine = Engine()

    calls = {"pe": 0, "strings": 0}

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.PE)

    def fake_pe(p):
        calls["pe"] += 1
        return {"resource_strings": []}

    def fake_strings(p, min_length):
        calls["strings"] += 1
        return ["X"]

    monkeypatch.setattr("iocx.engine.parse_pe", fake_pe)
    monkeypatch.setattr("iocx.engine.extract_strings", fake_strings)

    engine.extract_from_file(str(path))
    engine.extract_from_file(str(path))

    assert calls["pe"] == 1
    assert calls["strings"] == 1


def test_cache_disabled(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"abc")

    engine = Engine(EngineConfig(enable_cache=False))

    calls = {"pe": 0, "strings": 0}

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.PE)

    def fake_pe(p):
        calls["pe"] += 1
        return {}

    def fake_strings(p, min_length):
        calls["strings"] += 1
        return ["X"]

    monkeypatch.setattr("iocx.engine.parse_pe", fake_pe)
    monkeypatch.setattr("iocx.engine.extract_strings", fake_strings)

    engine.extract_from_file(str(path))
    engine.extract_from_file(str(path))

    assert calls["pe"] == 2
    assert calls["strings"] == 2


# ------------------------------------------------------------
# _post_process behaviour
# ------------------------------------------------------------

def test_post_process_merges_and_suppresses_overlaps(monkeypatch):
    engine = Engine()

    # Two overlapping detections: second is shorter and should be suppressed
    raw = {
        "urls": [
            make_det("http://long", 0, 12, "urls"),
            make_det("http://sh", 2, 10, "urls"),
        ],
        "ips": [
            make_det("1.2.3.4", 20, 27, "ips"),
        ],
    }

    merged = engine._post_process(raw)

    # Only the longer URL survives
    assert merged["urls"] == ["http://long"]
    assert merged["ips"] == ["1.2.3.4"]


# ------------------------------------------------------------
# _is_file
# ------------------------------------------------------------

def test_is_file_true(monkeypatch):
    engine = Engine()
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: True)
    assert engine._is_file("x") is True


def test_is_file_false(monkeypatch):
    engine = Engine()
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)
    assert engine._is_file("x") is False


def test_is_file_exception(monkeypatch):
    engine = Engine()
    monkeypatch.setattr(
        "iocx.engine.os.path.exists",
        lambda p: (_ for _ in ()).throw(Exception("boom")),
    )
    assert engine._is_file("x") is False


def test_extract_file_and_text_paths(monkeypatch, mock_detectors):
    engine = Engine()

    # Case 1: file path
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: True)
    monkeypatch.setattr(engine, "extract_from_file", lambda p, **kw: {"ok": "file"})
    assert engine.extract("x") == {"ok": "file"}

    # Case 2: text path
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)
    monkeypatch.setattr(engine, "extract_from_text", lambda t, **kw: {"ok": "text"})
    assert engine.extract("x") == {"ok": "text"}

# -----------------------------------------------------------
# Detector outcomes
# -----------------------------------------------------------

def test_engine_handles_invalid_detector_output(monkeypatch):
    def bad_detector(_):
        return 123 # invalid → triggers skip branch

    monkeypatch.setattr(
        "iocx.detectors.all_detectors",
        lambda: {"bad": bad_detector}
    )

    engine = Engine()
    result = engine.extract_from_text("hello")

    assert "bad" not in result["iocs"]


def test_engine_skips_malformed_detection_items(monkeypatch):
    def malformed_detector(_):
        return ["not-a-detection", (1, 2, 3)] # both malformed

    monkeypatch.setattr(
        "iocx.detectors.all_detectors",
        lambda: {"malformed": malformed_detector}
    )

    engine = Engine()
    result = engine.extract_from_text("hello")

    assert "malformed" not in result["iocs"]


def test_transformer_exception_is_caught(caplog, exploding_transformer):
    # Capture warnings
    import logging
    caplog.set_level(logging.WARNING, logger="iocx")

    # Create engine
    engine = Engine()

    # Inject our exploding transformer into the engine's registry
    engine._plugin_registry.transformers = [exploding_transformer]

    # Run extraction (any text is fine)
    result = engine.extract_from_text("hello world")

    # Assert the warning was logged
    assert any(
        "exploding-transformer" in rec.message and "failed" in rec.message
        for rec in caplog.records
    ), "Expected transformer failure warning not logged"

    # Assert extraction still completed normally
    assert "iocs" in result
    assert isinstance(result["iocs"], dict)


def test_invalid_detector_output_is_skipped(monkeypatch):
    import iocx.detectors.registry as det_registry

    # Fake detector that returns a completely invalid type
    def bad_detector(text):
        return 123 # invalid → should be skipped

    monkeypatch.setitem(det_registry._DETECTORS, "bad", bad_detector)

    engine = Engine()
    result = engine.extract_from_text("hello world")

    # The invalid detector should not exist in output
    assert "bad" not in result["iocs"]

    assert isinstance(result["iocs"], dict)


def test_invalid_detector_dict_with_no_valid_lists_is_skipped(monkeypatch):
    """
    A detector that returns a dict whose values are NOT lists should be skipped
    """
    from iocx.detectors import registry as det_registry

    # Detector returns a dict, but with no list values → should now be skipped
    def bad_detector(text):
        return {"foo": 123, "bar": None, "baz": 999}

    # Inject into detector registry
    monkeypatch.setitem(det_registry._DETECTORS, "bad", bad_detector)

    engine = Engine()
    result = engine.extract_from_text("hello world")

    # The invalid detector should NOT appear in the IOC output
    assert "bad" not in result["iocs"]

    # Engine should still return a valid IOC structure
    assert isinstance(result["iocs"], dict)


def test_detector_output_detection_objects(monkeypatch):
    from iocx.detectors import registry as det_registry

    def good_detector(text):
        return [Detection("abc", 0, 3, "testcat")]

    monkeypatch.setitem(det_registry._DETECTORS, "good", good_detector)

    engine = Engine()
    result = engine.extract_from_text("abc")

    assert result["iocs"]["testcat"] == ["abc"]


def test_detector_output_tuple_is_normalised(monkeypatch):
    from iocx.detectors import registry as det_registry

    # value, start, end, category
    def tuple_detector(text):
        return [("xyz", 0, 3, "tuplecat")]

    monkeypatch.setitem(det_registry._DETECTORS, "tuple", tuple_detector)

    engine = Engine()
    result = engine.extract_from_text("xyz")

    assert result["iocs"]["tuplecat"] == ["xyz"]


def test_detector_malformed_items_are_skipped(monkeypatch):
    from iocx.detectors import registry as det_registry

    # Includes:
    # - valid tuple
    # - malformed tuple (wrong length)
    # - completely invalid type
    def bad_items_detector(text):
        return [
            ("ok", 0, 2, "mixedcat"), # valid
            ("bad", 0, 3), # invalid tuple → should be skipped
            123, # invalid type → should be skipped
        ]

    monkeypatch.setitem(det_registry._DETECTORS, "mixed", bad_items_detector)

    engine = Engine()
    result = engine.extract_from_text("ok bad 123")

    # Only the valid one should survive
    assert result["iocs"]["mixedcat"] == ["ok"]


def test_detector_plugin_exception_is_logged_and_skipped(caplog, exploding_detector):
    """
    Ensures that when a detector plugin raises an exception:
    - the engine logs a warning
    - the engine does not crash
    - extraction still succeeds
    - the detector category is not added to the IOC output
    """
    import logging
    caplog.set_level(logging.WARNING, logger="iocx")

    engine = Engine()

    # Inject the exploding detector plugin
    engine._plugin_registry.detectors = [exploding_detector]

    result = engine.extract_from_text("hello world")

    # 1. Warning must be logged
    assert any(
        "exploding-detector" in rec.message
        and "failed" in rec.message
        for rec in caplog.records
    ), "Expected detector failure warning not logged"

    # 2. Engine must continue running
    assert "iocs" in result
    assert isinstance(result["iocs"], dict)

    # 3. The detector category must NOT appear in the IOC output
    assert "exploding-detector" not in result["iocs"]


def test_detector_tuple_normalised_to_detection(tuple_detector):
    engine = Engine()
    engine._plugin_registry.detectors = [tuple_detector]

    result = engine.extract_from_text("abc")

    # The tuple should be normalised into a Detection and grouped under its category
    assert result["iocs"]["tuplecat"] == ["abc"]


def test_detector_malformed_items_are_skipped(malformed_detector):
    engine = Engine()
    engine._plugin_registry.detectors = [malformed_detector]

    result = engine.extract_from_text("hello")

    # The malformed detector should produce no valid detections
    assert "malformed-detector" not in result["iocs"]


def test_detector_malformed_items_trigger_else_and_are_skipped(malformed_detector):
    """
    Ensures that malformed detector output items hit the `else: continue` block
    and produce no valid detections.
    """

    engine = Engine()
    engine._plugin_registry.detectors = [malformed_detector]

    result = engine.extract_from_text("hello world")

    # The malformed detector should produce no valid detections
    assert "malformed-detector" not in result["iocs"]

    # Engine should still return a valid IOC structure
    assert isinstance(result["iocs"], dict)
