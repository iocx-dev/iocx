# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

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
            "machine_name": "AMD64",
            "subsystem": 3, # WINDOWS_CUI
            "subsystem_name": "WINDOWS_CUI",
            "timestamp": 0,
        }
    }

    result = analyse_extended(None, metadata, [])
    header = extract(result, "header")["metadata"]

    assert header["machine_name"] == "AMD64"
    assert header["subsystem_name"] == "WINDOWS_CUI"


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


class TestAnalyseExtendedHeaderPassthrough:

    def test_header_detection_matches_input_header_verbatim(self):
        """Post-refactor, the extended header block is a verbatim pass-through
        of the parser's header dict. No decoding, no enrichment."""
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {
                "entry_point": 0x1000,
                "image_base": 0x140000000,
                "subsystem": 3,
                "subsystem_name": "WINDOWS_CUI",
                "timestamp": 1700000000,
                "machine": 0x8664,
                "machine_name": "AMD64",
                "characteristics": 0x22,
            },
            "optional_header": None,
            "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        header_detection = next(d for d in detections if d["value"] == "header")
        # The detection's metadata should equal the input header exactly
        assert header_detection["metadata"] == metadata["header"]

    def test_no_subsystem_human_field_added(self):
        """Post-refactor, the legacy subsystem_human field is removed."""
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {"subsystem": 3, "subsystem_name": "WINDOWS_CUI"},
            "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        header_detection = next(d for d in detections if d["value"] == "header")
        assert "subsystem_human" not in header_detection["metadata"]

    def test_no_machine_human_field_added(self):
        """Post-refactor, the legacy machine_human field is removed."""
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {"machine": 0x8664, "machine_name": "AMD64"},
            "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        header_detection = next(d for d in detections if d["value"] == "header")
        assert "machine_human" not in header_detection["metadata"]

class TestAnalyseExtendedSummary:

    def test_summary_counts_correct(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [
                {"dll": "a.dll", "function": "foo", "ordinal": None},
                {"dll": "a.dll", "function": "bar", "ordinal": None},
                {"dll": "b.dll", "function": "baz", "ordinal": None},
            ],
            "delayed_imports": [
                {"dll": "c.dll", "function": "qux", "ordinal": None},
            ],
            "bound_imports": [],
            "exports": [{"name": "foo", "ordinal": 1, "forwarder": None},
                        {"name": "bar", "ordinal": 2, "forwarder": None}],
            "resources": [{
                "type": "RT_ICON",
                "name": None,
                "language": 1033,
                "language_name": "en-US",
                "codepage": None,
                "size": 100,
                "entropy": 4.5,
                "rva": 0x1000,
                "raw_offset": 0x400,
                "errors": None,
            }],
            "tls": {"start_address": 1, "end_address": 2, "callbacks": None},
            "signatures": [{"signer": "test"}],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        summary = next(d for d in detections if d["value"] == "summary")["metadata"]

        assert summary["dll_count"] == 2
        assert summary["import_count"] == 3
        assert summary["delayed_import_count"] == 1
        assert summary["bound_import_count"] == 0
        assert summary["export_count"] == 2
        assert summary["resource_count"] == 1
        assert summary["has_tls"] is True
        assert summary["has_signature"] is True

    def test_summary_with_no_data(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        summary = next(d for d in detections if d["value"] == "summary")["metadata"]

        assert summary["dll_count"] == 0
        assert summary["import_count"] == 0
        assert summary["has_tls"] is False
        assert summary["has_signature"] is False

class TestAnalyseExtendedImports:

    def test_imports_grouped_by_dll(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [
                {"dll": "a.dll", "function": "foo", "ordinal": None},
                {"dll": "b.dll", "function": "bar", "ordinal": None},
                {"dll": "a.dll", "function": "baz", "ordinal": None},
            ],
            "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        imports = [d for d in detections if d["value"] == "imports"]

        # Two DLLs in alphabetical order
        assert len(imports) == 2
        assert imports[0]["metadata"]["dll"] == "a.dll"
        assert imports[1]["metadata"]["dll"] == "b.dll"
        # Functions sorted alphabetically within each DLL
        assert imports[0]["metadata"]["functions"] == ["baz", "foo"]

    def test_ordinal_only_imports_displayed_as_hash(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [
                {"dll": "a.dll", "function": None, "ordinal": 42},
            ],
            "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        imports = next(d for d in detections if d["value"] == "imports")
        assert imports["metadata"]["functions"] == ["#42"]

    def test_imports_with_mixed_name_and_ordinal_sorted(self):
        """Named functions first, then ordinals."""
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [
                {"dll": "a.dll", "function": None, "ordinal": 5},
                {"dll": "a.dll", "function": "Bar", "ordinal": None},
                {"dll": "a.dll", "function": "Alpha", "ordinal": None},
            ],
            "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        imports = next(d for d in detections if d["value"] == "imports")
        assert imports["metadata"]["functions"] == ["Alpha", "Bar", "#5"]

class TestAnalyseExtendedConditionalSections:

    def test_no_delayed_imports_section_when_empty(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        delayed = [d for d in detections if d["value"] == "delayed_imports"]
        assert delayed == []

    def test_no_tls_section_when_none(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        tls = [d for d in detections if d["value"] == "tls_directory"]
        assert tls == []

    def test_no_signature_section_when_empty(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        sig = [d for d in detections if d["value"] == "signature"]
        assert sig == []

    def test_no_rich_header_section_when_none(self):
        from iocx.analysis.extended import analyse_extended

        metadata = {
            "import_details": [], "delayed_imports": [], "bound_imports": [],
            "exports": [], "resources": [], "tls": None, "signatures": [],
            "header": {}, "optional_header": None, "rich_header": None,
        }
        detections = analyse_extended(None, metadata, [])
        rich = [d for d in detections if d["value"] == "rich_header"]
        assert rich == []
