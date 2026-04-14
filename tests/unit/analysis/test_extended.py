import pytest
from iocx.analysis.extended import analyse_extended

def extract(detections, value):
    """Helper to pull a detection by its 'value' field."""
    for d in detections:
        if d["value"] == value:
            return d
    return None


def test_summary_block_counts_correctly():
    metadata = {
        "import_details": [
            {"dll": "A.dll", "function": "f1", "ordinal": None},
            {"dll": "A.dll", "function": "f2", "ordinal": None},
            {"dll": "B.dll", "function": None, "ordinal": 5},
        ],
        "delayed_imports": [{"dll": "C.dll", "function": "x", "ordinal": None}],
        "bound_imports": [{"dll": "D.dll", "timestamp": 123}],
        "exports": [{"name": "foo", "ordinal": 1, "address": 0, "forwarder": None}],
        "resources": [{"type": "RT_ICON", "entropy": 3.0}],
        "tls": {"start_address": 1},
        "signatures": [{"address": 10, "size": 20}],
    }

    result = analyse_extended(None, metadata, [])
    summary = extract(result, "summary")["metadata"]

    assert summary["dll_count"] == 2
    assert summary["import_count"] == 3
    assert summary["delayed_import_count"] == 1
    assert summary["bound_import_count"] == 1
    assert summary["export_count"] == 1
    assert summary["resource_count"] == 1
    assert summary["has_tls"] is True
    assert summary["has_signature"] is True


def test_grouped_imports_sorted_and_ordinal_handling():
    metadata = {
        "import_details": [
            {"dll": "B.dll", "function": None, "ordinal": 3},
            {"dll": "A.dll", "function": "zeta", "ordinal": None},
            {"dll": "A.dll", "function": "alpha", "ordinal": None},
        ]
    }

    result = analyse_extended(None, metadata, [])
    imports = [d for d in result if d["value"] == "imports"]

    assert imports[0]["metadata"]["dll"] == "A.dll"
    assert imports[0]["metadata"]["functions"] == ["alpha", "zeta"]

    assert imports[1]["metadata"]["dll"] == "B.dll"
    assert imports[1]["metadata"]["functions"] == ["#3"]


def test_delayed_imports_grouping_and_sorting():
    metadata = {
        "delayed_imports": [
            {"dll": "X.dll", "function": None, "ordinal": 2},
            {"dll": "X.dll", "function": "foo", "ordinal": None},
        ]
    }

    result = analyse_extended(None, metadata, [])
    delayed = extract(result, "delayed_imports")["metadata"]

    assert delayed["dll"] == "X.dll"
    assert delayed["functions"] == ["foo", "#2"]


def test_bound_imports_sorted():
    metadata = {
        "bound_imports": [
            {"dll": "z.dll", "timestamp": 1},
            {"dll": "a.dll", "timestamp": 2},
        ]
    }

    result = analyse_extended(None, metadata, [])
    bound = extract(result, "bound_imports")["metadata"]["entries"]

    assert bound[0]["dll"] == "a.dll"
    assert bound[1]["dll"] == "z.dll"


def test_exports_summary():
    metadata = {
        "exports": [
            {"name": "Foo", "forwarder": None},
            {"name": None, "forwarder": "Bar.Forward"},
        ]
    }

    result = analyse_extended(None, metadata, [])
    exports = extract(result, "exports")["metadata"]

    assert exports["count"] == 2
    assert exports["names"] == ["Foo"]
    assert len(exports["forwarded"]) == 1


def test_tls_directory_included():
    metadata = {"tls": {"start_address": 10, "end_address": 20}}
    result = analyse_extended(None, metadata, [])
    tls = extract(result, "tls_directory")["metadata"]

    assert tls["start_address"] == 10
    assert tls["end_address"] == 20


def test_header_human_fields():
    metadata = {
        "header": {
            "machine": 0x8664, # AMD64
            "subsystem": 3, # Windows CUI
            "timestamp": 0,
        }
    }

    result = analyse_extended(None, metadata, [])
    header = extract(result, "header")["metadata"]

    assert header["machine_human"] == "AMD64"
    assert header["subsystem_human"] == "Windows CUI"


def test_optional_header_included():
    metadata = {"optional_header": {"file_alignment": 512}}
    result = analyse_extended(None, metadata, [])
    opt = extract(result, "optional_header")["metadata"]

    assert opt["file_alignment"] == 512


def test_rich_header_included():
    metadata = {"rich_header": {"key": "value"}}
    result = analyse_extended(None, metadata, [])
    rich = extract(result, "rich_header")["metadata"]

    assert rich == {"key": "value"}


def test_signature_block_included():
    metadata = {"signatures": [{"address": 1, "size": 2}]}
    result = analyse_extended(None, metadata, [])
    sig = extract(result, "signature")["metadata"]

    assert sig["has_signature"] is True
    assert sig["entries"][0]["address"] == 1


def test_resource_summary():
    metadata = {
        "resources": [
            {"type": "RT_ICON", "entropy": 3.0},
            {"type": "RT_ICON", "entropy": 5.0},
        ]
    }

    result = analyse_extended(None, metadata, [])
    res = extract(result, "resources")["metadata"]

    assert res["count"] == 2
    assert res["types"] == ["RT_ICON"]
    assert res["entropy_min"] == 3.0
    assert res["entropy_max"] == 5.0
    assert res["entropy_avg"] == 4.0


def test_empty_metadata_produces_minimal_output():
    result = analyse_extended(None, {}, [])
    summary = extract(result, "summary")["metadata"]

    assert summary["dll_count"] == 0
    assert summary["import_count"] == 0
    assert summary["resource_count"] == 0
    assert summary["has_tls"] is False
    assert summary["has_signature"] is False
