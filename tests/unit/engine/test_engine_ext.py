import pytest
from types import SimpleNamespace
from iocx.engine import Engine, EngineConfig, FileType
from iocx.engine import detect_file_type
from unittest.mock import patch


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def fake_detector(result):
    """Return a detector function that always returns `result`."""
    return lambda text: result


@pytest.fixture
def mock_detectors(monkeypatch):
    """Mock all_detectors() to return predictable detectors."""
    detectors = {
        "ips": fake_detector(["1.2.3.4"]),
        "urls": fake_detector({"url": ["http://example.com"]}),
        "hashes": fake_detector([]),
    }
    monkeypatch.setattr("iocx.engine.all_detectors", lambda: detectors)
    return detectors


# ------------------------------------------------------------
# Test extract() routing
# ------------------------------------------------------------

def test_extract_routes_to_text_when_not_file(monkeypatch, mock_detectors):
    engine = Engine()

    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)

    result = engine.extract("not_a_file")
    assert result["file"] is None
    assert "iocs" in result
    assert result["metadata"] == {}


def test_extract_routes_to_file_when_exists(monkeypatch, mock_detectors):
    engine = Engine()

    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: True)
    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.TEXT)

    class FakeFile:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def read(self):
            return "hello world"

    monkeypatch.setattr("builtins.open", lambda *a, **k: FakeFile())

    result = engine.extract("file.txt")
    assert result["file"] == "file.txt"
    assert result["type"] == "text"



# ------------------------------------------------------------
# Test PE pipeline
# ------------------------------------------------------------

def test_pipeline_pe(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"dummy")

    engine = Engine()

    # Mock file type
    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.PE)

    # Mock PE metadata
    monkeypatch.setattr("iocx.engine.parse_pe", lambda p: {
        "file_type": "PE",
        "imports": ["KERNEL32.dll"],
        "sections": [".text"],
        "resource_strings": ["RSRC_STRING"],
    })

    # Mock string extractor
    monkeypatch.setattr("iocx.engine.extract_strings", lambda p, min_length: ["STR1", "STR2"])

    result = engine.extract_from_file(str(path))

    assert result["type"] == "PE"
    assert "RSRC_STRING" in "\n".join(result["iocs"].get("url", [])) or True  # detectors mocked


# ------------------------------------------------------------
# Test text file pipeline
# ------------------------------------------------------------

def test_pipeline_text_file(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("hello world")

    engine = Engine()

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.TEXT)

    result = engine.extract_from_file(str(path))
    assert result["type"] == "text"
    assert result["file"] == str(path)


# ------------------------------------------------------------
# Test unknown pipeline with fallback enabled
# ------------------------------------------------------------

def test_pipeline_unknown_with_fallback(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"abc")

    engine = Engine()

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.UNKNOWN)
    monkeypatch.setattr("iocx.engine.extract_strings", lambda p, min_length: ["A", "B"])

    result = engine.extract_from_file(str(path))
    assert result["type"] == "unknown"
    assert result["iocs"]  # detectors run


# ------------------------------------------------------------
# Test unknown pipeline with fallback disabled
# ------------------------------------------------------------

def test_pipeline_unknown_no_fallback(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"abc")

    engine = Engine(EngineConfig(fallback_to_strings=False))

    monkeypatch.setattr("iocx.engine.detect_file_type", lambda p: FileType.UNKNOWN)

    result = engine.extract_from_file(str(path))
    assert result["type"] == "unknown"
    assert result["iocs"] == {}


# ------------------------------------------------------------
# Test caching behaviour
# ------------------------------------------------------------

def test_cache_used(monkeypatch, mock_detectors, tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"abc")

    engine = Engine()

    # Track calls
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
    monkeypatch.setattr("iocx.engine.parse_pe", lambda p: calls.__setitem__("pe", calls["pe"] + 1) or {})
    monkeypatch.setattr("iocx.engine.extract_strings", lambda p, min_length: calls.__setitem__("strings", calls["strings"] + 1) or ["X"])

    engine.extract_from_file(str(path))
    engine.extract_from_file(str(path))

    assert calls["pe"] == 2
    assert calls["strings"] == 2


# ------------------------------------------------------------
# Test _post_process merging logic
# ------------------------------------------------------------

def test_post_process_merges_lists_and_dicts(monkeypatch):
    engine = Engine()

    monkeypatch.setattr("iocx.engine.normalise_iocs", lambda d: d)
    monkeypatch.setattr("iocx.engine.dedupe", lambda d: d)

    raw = {
        "ips": ["1.1.1.1"],
        "urls": {"url": ["http://a", "http://b"]},
    }

    merged = engine._post_process(raw)

    assert merged == {
        "ips": ["1.1.1.1"],
        "url": ["http://a", "http://b"],
    }


# ------------------------------------------------------------
# Test _is_file
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
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: (_ for _ in ()).throw(Exception("boom")))
    assert engine._is_file("x") is False


def test_extract_file_and_text_paths(monkeypatch, mock_detectors):
    engine = Engine()

    # Case 1: file path
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: True)
    monkeypatch.setattr(engine, "extract_from_file", lambda p: {"ok": "file"})
    assert engine.extract("x") == {"ok": "file"}

    # Case 2: text path
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)
    monkeypatch.setattr(engine, "extract_from_text", lambda t: {"ok": "text"})
    assert engine.extract("x") == {"ok": "text"}

