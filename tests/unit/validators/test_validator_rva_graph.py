# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.rva_graph import validate_rva_graph
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) size_of_image missing → early return
# ---------------------------------------------------------

def test_rva_graph_missing_size_of_image():
    metadata = {"optional_header": {}}
    analysis = {}
    issues = validate_rva_graph(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) malformed directory entry → first continue
# ---------------------------------------------------------

def test_rva_graph_malformed_directory_entry():
    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "data_directories": [
            {"rva": "bad", "size": 10}, # triggers continue
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 3) negative rva/size
# ---------------------------------------------------------

def test_rva_graph_negative_values():
    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": -1, "size": 10},
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_INVALID_RANGE in make_issue_list(issues)


# ---------------------------------------------------------
# 4) empty directory (0,0)
# ---------------------------------------------------------

def test_rva_graph_empty_directory():
    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": 0, "size": 0},
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert issues == []


def test_rva_graph_empty_directory_unexpected(monkeypatch):
    # Patch REQUIRED_NONZERO_DIRS to force the branch
    from iocx.validators import rva_graph
    monkeypatch.setattr(rva_graph, "REQUIRED_NONZERO_DIRS", {"dir"})

    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": 0, "size": 0},
        ]
    }

    issues = rva_graph.validate_rva_graph(metadata, analysis)

    assert ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED in [
        i["issue"] for i in issues
    ]


# ---------------------------------------------------------
# 5) zero-RVA non-zero size
# ---------------------------------------------------------

def test_rva_graph_zero_rva_nonzero_size():
    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": 0, "size": 50},
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE in make_issue_list(issues)


# ---------------------------------------------------------
# 6) directory in headers
# ---------------------------------------------------------

def test_rva_graph_in_headers():
    metadata = {"optional_header": {"size_of_image": 1000, "size_of_headers": 300}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": 100, "size": 50},
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_IN_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 7) out-of-range directory
# ---------------------------------------------------------

def test_rva_graph_out_of_range():
    metadata = {"optional_header": {"size_of_image": 200}}
    analysis = {
        "data_directories": [
            {"name": "dir", "rva": 150, "size": 100},
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE in make_issue_list(issues)


# ---------------------------------------------------------
# 8) overlay detection
# ---------------------------------------------------------

def test_rva_graph_overlay_detection():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "overlay_offset": 300,
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 500,
                "raw_address": 200,
            }
        ],
        "data_directories": [
            {"name": "dir", "rva": 250, "size": 10},
        ],
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_IN_OVERLAY in make_issue_list(issues)


# ---------------------------------------------------------
# 9) zero-length section skip
# ---------------------------------------------------------

def test_rva_graph_zero_length_section_skip():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "sections": [
            {
                "name": ".empty",
                "virtual_address": 1000,
                "virtual_size": 0,
                "raw_address": 500,
            }
        ],
        "data_directories": [
            {"name": "dir", "rva": 1000, "size": 10}, # lands exactly on zero-length section
        ],
    }
    issues = validate_rva_graph(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 10) not mapped to any section
# ---------------------------------------------------------

def test_rva_graph_not_mapped_to_section():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 100,
            }
        ],
        "data_directories": [
            {"name": "dir", "rva": 500, "size": 10}, # outside section
        ],
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 11) spans multiple sections
# ---------------------------------------------------------

def test_rva_graph_spans_multiple_sections():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "sections": [
            {"name": "A", "virtual_address": 100, "virtual_size": 100},
            {"name": "B", "virtual_address": 150, "virtual_size": 100},
        ],
        "data_directories": [
            {"name": "dir", "rva": 120, "size": 100}, # overlaps A and B
        ],
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS in make_issue_list(issues)


# ---------------------------------------------------------
# 12) directory overlap detection
# ---------------------------------------------------------

def test_rva_graph_directory_overlap():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "data_directories": [
            {"name": "A", "rva": 100, "size": 100},
            {"name": "B", "rva": 150, "size": 100}, # overlaps A
        ]
    }
    issues = validate_rva_graph(metadata, analysis)
    assert ReasonCodes.DATA_DIRECTORY_OVERLAP in make_issue_list(issues)


def test_rva_graph_directory_overlap_inner_continue():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "data_directories": [
            {
                "name": "A",
                "rva": 100,
                "size": 50, # valid → outer loop does NOT continue
            },
            {
                "name": "B",
                "rva": "bad", # invalid → triggers inner continue
                "size": 50,
            },
        ]
    }

    issues = validate_rva_graph(metadata, analysis)

    # No overlap issue should be produced because the inner loop continues
    assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(issues)
