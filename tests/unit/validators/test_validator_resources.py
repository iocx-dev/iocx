# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.resources import validate_resources
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


def test_resources_no_resources_struct():
    metadata = {"resources_struct": None}
    analysis = {}
    issues = validate_resources(metadata, analysis)
    assert issues == []


def test_resources_no_rsrc_section():
    metadata = {"resources_struct": {"root": {}}}
    analysis = {
        "sections": [{"name": ".text"}],
        "file_size": 1000,
        "overlay_offset": 500,
    }
    issues = validate_resources(metadata, analysis)
    assert issues == []


def test_resources_zero_length_directory():
    metadata = {
        "resources_struct": {
            "root": {"rva": 100, "size": 0, "entries": []}
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 100,
            "raw_address": 200,
            "raw_size": 100,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }
    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH in make_issue_list(issues)


def test_resources_directory_loop():
    loop = {"rva": 100, "size": 10, "entries": []}
    loop["entries"] = [{"is_directory": True, "directory": loop}]

    metadata = {"resources_struct": {"root": loop}}
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 200,
            "raw_address": 200,
            "raw_size": 200,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(issues)


def test_resources_entry_out_of_bounds():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": True,
                     "directory": {"rva": 9999, "size": 10, "entries": []}}
                ]
            }
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 200,
            "raw_address": 200,
            "raw_size": 200,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS in make_issue_list(issues)


def test_resources_zero_size_data():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 120, "data_size": 0, "raw_offset": 300}
                ]
            }
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 200,
            "raw_address": 200,
            "raw_size": 200,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS in make_issue_list(issues)


def test_resources_rva_out_of_bounds():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 9999, "data_size": 10, "raw_offset": 300}
                ]
            }
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 200,
            "raw_address": 200,
            "raw_size": 200,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS in make_issue_list(issues)


def test_resources_raw_out_of_bounds():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 120, "data_size": 50, "raw_offset": 980}
                ]
            }
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 200,
            "raw_address": 200,
            "raw_size": 200,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS in make_issue_list(issues)


def test_resources_overlay_overlap():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 120, "data_size": 100, "raw_offset": 450}
                ]
            }
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 300,
            "raw_address": 200,
            "raw_size": 300,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA in make_issue_list(issues)


def test_resources_raw_overlap_other_section():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 120, "data_size": 50, "raw_offset": 250}
                ]
            }
        }
    }
    analysis = {
        "sections": [
            {
                "name": ".rsrc",
                "virtual_address": 100,
                "virtual_size": 300,
                "raw_address": 200,
                "raw_size": 300,
            },
            {
                "name": ".text",
                "virtual_address": 1000,
                "virtual_size": 100,
                "raw_address": 240,
                "raw_size": 20,
            }
        ],
        "file_size": 1000,
        "overlay_offset": 900,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA in make_issue_list(issues)


def test_resources_va_overlap_other_section():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 100, "size": 10,
                "entries": [
                    {"is_directory": False,
                     "data_rva": 150, "data_size": 50, "raw_offset": 250}
                ]
            }
        }
    }
    analysis = {
        "sections": [
            {
                "name": ".rsrc",
                "virtual_address": 100,
                "virtual_size": 300,
                "raw_address": 200,
                "raw_size": 300,
            },
            {
                "name": ".text",
                "virtual_address": 140,
                "virtual_size": 100,
                "raw_address": 500,
                "raw_size": 100,
            }
        ],
        "file_size": 1000,
        "overlay_offset": 900,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA in make_issue_list(issues)


def test_resources_string_table_corrupt():
    metadata = {
        "resources_struct": {
            "root": {"rva": 100, "size": 10, "entries": []},
            "string_tables": [
                {"rva": 9999, "size": 20}
            ]
        }
    }
    analysis = {
        "sections": [{
            "name": ".rsrc",
            "virtual_address": 100,
            "virtual_size": 300,
            "raw_address": 200,
            "raw_size": 300,
        }],
        "file_size": 1000,
        "overlay_offset": 500,
    }

    issues = validate_resources(metadata, analysis)
    assert ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT in make_issue_list(issues)


def test_resources_directory_outside_rsrc_skips_validation():
    metadata = {
        "resources_struct": {
            "root": {
                "rva": 9999, # OUTSIDE .rsrc VA range
                "size": 10,
                "entries": []
            }
        }
    }

    analysis = {
        "sections": [
            {
                "name": ".rsrc",
                "virtual_address": 100,
                "virtual_size": 200, # .rsrc covers VA 100–300
                "raw_address": 200,
                "raw_size": 200,
            }
        ],
        "file_size": 5000,
        "overlay_offset": 4000,
    }

    issues = validate_resources(metadata, analysis)

    # Because the directory is outside .rsrc, validate_directory() returns immediately
    # → no issues should be produced
    assert issues == []


class TestLanguageLayerNamedEntry:
    """
    Cover the depth-2 named-entry detection: a Language-layer directory
    that contains a named entry instead of an integer LCID.
    """

    def _make_resources_with_named_language_entry(self) -> dict:
        """
        Build a minimal resources_struct dict with this shape:
            Type (depth 0)
              └─ Name (depth 1)
                  └─ Language (depth 2)  ← contains a named entry (anomaly)
                      └─ data leaf
        """
        # Data leaf at depth 3 — well-formed, in-bounds
        data_leaf_entry = {
            "name": None,
            "id": 0x0409,
            "is_directory": False,
            "directory": None,
            "data_rva": 0x1100,
            "data_size": 100,
            "raw_offset": 0x500,
        }

        # Depth 2: Language directory containing a NAMED entry (the anomaly)
        # plus a valid ID entry as a sibling, to prove the validator emits
        # per-violation rather than per-directory.
        lang_dir = {
            "rva": 0x1080,
            "size": 32,
            "entries": [
                {
                    "name": "EN-US",  # ← anomaly: named instead of LCID
                    "id": None,
                    "is_directory": True,
                    "directory": {
                        "rva": 0x1090,
                        "size": 24,
                        "entries": [data_leaf_entry],
                    },
                    "data_rva": None,
                    "data_size": None,
                    "raw_offset": None,
                },
            ],
        }

        # Depth 1: Name directory
        name_dir = {
            "rva": 0x1040,
            "size": 24,
            "entries": [
                {
                    "name": None,
                    "id": 1,
                    "is_directory": True,
                    "directory": lang_dir,
                    "data_rva": None,
                    "data_size": None,
                    "raw_offset": None,
                },
            ],
        }

        # Depth 0: Type directory (root)
        root = {
            "rva": 0x1000,
            "size": 24,
            "entries": [
                {
                    "name": None,
                    "id": 16,  # RT_VERSION
                    "is_directory": True,
                    "directory": name_dir,
                    "data_rva": None,
                    "data_size": None,
                    "raw_offset": None,
                },
            ],
        }

        return {
            "root": root,
            "string_tables": [],
        }

    def _make_analysis(self) -> dict:
        return {
            "sections": [{
                "name": ".rsrc",
                "virtual_address": 0x1000,
                "virtual_size": 0x2000,
                "raw_address": 0x400,
                "raw_size": 0x2000,
            }],
            "file_size": 0x10000,
            "overlay_offset": 0x9000,
        }

    def test_named_language_entry_flagged(self):
        from iocx.reason_codes import ReasonCodes
        from iocx.validators.resources import validate_resources

        resources = self._make_resources_with_named_language_entry()
        metadata = {"resources_struct": resources}
        issues = validate_resources(metadata, self._make_analysis())

        codes = [i["issue"] for i in issues]
        assert ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID in codes

        # Confirm the details payload is shaped correctly
        details = [
            i["details"] for i in issues
            if i["issue"] == ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID
        ]
        assert len(details) == 1
        assert details[0]["name"] == "EN-US"
        assert details[0]["rva"] == 0x1080  # the language directory's RVA
