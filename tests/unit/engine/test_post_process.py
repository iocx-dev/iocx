import pytest
from iocx.engine import Engine, EngineConfig


@pytest.fixture
def engine():
    # Disable cache for deterministic tests
    return Engine(EngineConfig(enable_cache=False))


def test_post_process_merges_list_detectors(engine):
    raw = {
        "ips": ["1.1.1.1", "2.2.2.2"],
        "emails": ["a@example.com"],
    }

    result = engine._post_process(raw)

    assert result["ips"] == ["1.1.1.1", "2.2.2.2"]
    assert result["emails"] == ["a@example.com"]


def test_post_process_merges_dict_detectors(engine):
    raw = {
        "urls": {
            "urls": ["http://example.com"],
            "domains": ["example.com"],
        }
    }

    result = engine._post_process(raw)

    assert result["urls"] == ["http://example.com"]
    assert result["domains"] == ["example.com"]


def test_post_process_merges_mixed_types(engine):
    raw = {
        "ips": ["1.1.1.1"],
        "urls": {
            "urls": ["http://example.com"],
            "domains": ["example.com"],
        },
        "emails": ["a@example.com"],
    }

    result = engine._post_process(raw)

    assert result["ips"] == ["1.1.1.1"]
    assert result["urls"] == ["http://example.com"]
    assert result["domains"] == ["example.com"]
    assert result["emails"] == ["a@example.com"]


def test_post_process_dedupes_across_detectors(engine):
    raw = {
        "urls": {
            "urls": ["http://example.com", "http://example.com"],
            "domains": ["example.com"],
        },
        "domains": ["example.com"],  # duplicate from another detector
    }

    result = engine._post_process(raw)

    assert result["urls"] == ["http://example.com"]
    assert result["domains"] == ["example.com"]


def test_post_process_handles_empty(engine):
    raw = {}
    result = engine._post_process(raw)
    assert result == {}


def test_post_process_handles_empty_lists(engine):
    raw = {
        "urls": {"urls": [], "domains": []},
        "ips": [],
    }
    result = engine._post_process(raw)
    assert result == {"urls": [], "domains": [], "ips": []}
