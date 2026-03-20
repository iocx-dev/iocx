import os
import pytest

from iocx.engine import Engine, EngineConfig, FileType
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
    monkeypatch.setattr(engine, "extract_from_file", lambda p: {"ok": "file"})
    assert engine.extract("x") == {"ok": "file"}

    # Case 2: text path
    monkeypatch.setattr("iocx.engine.os.path.exists", lambda p: False)
    monkeypatch.setattr(engine, "extract_from_text", lambda t: {"ok": "text"})
    assert engine.extract("x") == {"ok": "text"}
