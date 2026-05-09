# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.entrypoint import validate_entrypoint, _map_rva_to_file_offset
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) No extended header → early return
# ---------------------------------------------------------

def test_entrypoint_no_extended_header():
    metadata = {}
    analysis = {"extended": []}
    issues = validate_entrypoint(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) No entry_point → early return
# ---------------------------------------------------------

def test_entrypoint_missing_entry_point():
    metadata = {}
    analysis = {"extended": [{"value": "header", "metadata": {}}]}
    issues = validate_entrypoint(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 3) EP <= 0
# ---------------------------------------------------------

def test_entrypoint_zero_or_negative():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 0}}],
        "sections": [],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_ZERO_OR_NEGATIVE in make_issue_list(issues)


# ---------------------------------------------------------
# 4) EP inside headers
# ---------------------------------------------------------

def test_entrypoint_in_headers():
    metadata = {"optional_header": {"size_of_headers": 300}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 100}}],
        "sections": [],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 5) No sections → return after header checks
# ---------------------------------------------------------

def test_entrypoint_no_sections():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 500}}],
        "sections": [],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 6) EP not mapping to any section
# ---------------------------------------------------------

def test_entrypoint_out_of_bounds_within_image():
    metadata = {"optional_header": {"size_of_image": 2000}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 1500}}],
        "sections": [
            {"name": ".text", "virtual_address": 0, "virtual_size": 1000},
        ],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_OUT_OF_BOUNDS in make_issue_list(issues)


def test_entrypoint_out_of_bounds_beyond_image():
    metadata = {"optional_header": {"size_of_image": 1000}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 2000}}],
        "sections": [
            {"name": ".text", "virtual_address": 0, "virtual_size": 500},
        ],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_OUT_OF_BOUNDS in make_issue_list(issues)


# ---------------------------------------------------------
# 7) Section not executable
# ---------------------------------------------------------

def test_entrypoint_section_not_executable():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 150}}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 100,
                "characteristics": 0, # not executable
            }
        ],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_SECTION_NOT_EXECUTABLE in make_issue_list(issues)


# ---------------------------------------------------------
# 8) EP in non-code section
# ---------------------------------------------------------

def test_entrypoint_in_non_code_section():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 150}}],
        "sections": [
            {
                "name": ".rsrc",
                "virtual_address": 100,
                "virtual_size": 100,
                "characteristics": 0, # not code
            }
        ],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_NON_CODE_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 9) EP in discardable section
# ---------------------------------------------------------

def test_entrypoint_in_discardable_section():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 150}}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 100,
                "characteristics": 0x02000000 | 0x20000000, # discardable + exec
            }
        ],
    }
    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_DISCARDABLE_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 10) Zero-length section
# ---------------------------------------------------------

def test_entrypoint_zero_length_section():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 120}}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 0, # zero-length
                "raw_address": 200,
                "raw_size": 100,
                "characteristics": 0x20000000, # executable
            }
        ],
    }

    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION in make_issue_list(issues)


# ---------------------------------------------------------
# 11) EP beyond virtual size
# ---------------------------------------------------------

def test_entrypoint_beyond_virtual_size():
    metadata = {"optional_header": {}}
    analysis = {
        "extended": [{"value": "header", "metadata": {"entry_point": 180}}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 50, # ends at 150
                "raw_address": 200,
                "raw_size": 200,
                "characteristics": 0x20000000,
            }
        ],
    }

    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION in make_issue_list(issues)


# ---------------------------------------------------------
# 12) EP in overlay
# ---------------------------------------------------------

def test_entrypoint_in_overlay():
    metadata = {"optional_header": {}}
    analysis = {
        "overlay_offset": 450,
        "extended": [{"value": "header", "metadata": {"entry_point": 200}}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 200,
                "raw_address": 400,
                "raw_size": 300,
                "characteristics": 0x20000000,
            }
        ],
    }

    issues = validate_entrypoint(metadata, analysis)
    assert ReasonCodes.ENTRYPOINT_IN_OVERLAY in make_issue_list(issues)


def test_map_rva_to_file_offset_continue_branch():
    sections = [
        {
            "virtual_address": 100,
            "virtual_size": 50,
            # raw_address missing → triggers continue
            "raw_size": 100,
        }
    ]

    result = _map_rva_to_file_offset(sections, 120)
    assert result is None


def test_map_rva_to_file_offset_return_none():
    sections = [
        {
            "virtual_address": 100,
            "virtual_size": 50,
            "raw_address": 200,
            "raw_size": 50,
        }
    ]

    # EP outside VA range → no match → return None
    result = _map_rva_to_file_offset(sections, 999)
    assert result is None
