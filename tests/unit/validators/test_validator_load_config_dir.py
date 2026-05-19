# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.load_config_directory import validate_load_config_directory, _map_rva_to_raw
from iocx.reason_codes import ReasonCodes


def _base():
    """Return minimal valid metadata structures."""
    internal = {"optional_header_magic": 0x10B} # PE32
    metadata = {"optional_header": {"size_of_image": 0x2000}}
    analysis = {
        "data_directories": [
            {"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": 0x1000, "size": 0x100}
        ],
        "sections": [
            {
                "name": ".data",
                "virtual_address": 0x1000,
                "virtual_size": 0x1000,
                "raw_address": 0x200,
                "characteristics": 0x80000000, # writable
            }
        ],
        "overlay_offset": None,
        "load_config": {},
    }
    return internal, metadata, analysis


# ---------------------------------------------------------
# 1. Directory missing → no issues
# ---------------------------------------------------------
def test_no_directory():
    internal, metadata, analysis = _base()
    analysis["data_directories"] = []
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2. Too small
# ---------------------------------------------------------
def test_load_config_too_small():
    internal, metadata, analysis = _base()
    analysis["data_directories"][0]["size"] = 0x20 # < 0x48
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_TOO_SMALL for i in issues)


# ---------------------------------------------------------
# 3. Truncated
# ---------------------------------------------------------
def test_load_config_truncated():
    internal, metadata, analysis = _base()
    analysis["load_config"]["parsed_size"] = 0x20
    analysis["data_directories"][0]["size"] = 0x80
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_TRUNCATED for i in issues)


# ---------------------------------------------------------
# 4. Guard CF inconsistent
# ---------------------------------------------------------
def test_guard_cf_inconsistent():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({
        "guard_cf_check_function_pointer": 0x1234,
        "guard_cf_dispatch_function_pointer": 0x5678,
        "guard_cf_function_table": 0,
        "guard_cf_function_count": 0,
    })
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_GUARD_CF_INCONSISTENT for i in issues)


# ---------------------------------------------------------
# 5. Cookie unmapped
# ---------------------------------------------------------
def test_cookie_unmapped():
    internal, metadata, analysis = _base()
    analysis["load_config"]["security_cookie_rva"] = 0x5000 # outside section
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_COOKIE_INVALID for i in issues)


# ---------------------------------------------------------
# 6. Cookie in non-writable section
# ---------------------------------------------------------
def test_cookie_non_writable():
    internal, metadata, analysis = _base()
    analysis["sections"][0]["characteristics"] = 0 # not writable
    analysis["load_config"]["security_cookie_rva"] = 0x1000
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(
        i["issue"] == ReasonCodes.LOAD_CONFIG_COOKIE_INVALID
        and i["details"]["reason"] == "non_writable_section"
        for i in issues
    )


# ---------------------------------------------------------
# 7. Cookie in overlay
# ---------------------------------------------------------
def test_cookie_in_overlay():
    internal, metadata, analysis = _base()
    analysis["overlay_offset"] = 0x300 # raw offset threshold
    analysis["load_config"]["security_cookie_rva"] = 0x1100
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_COOKIE_IN_OVERLAY for i in issues)


# ---------------------------------------------------------
# 8. SEH missing table RVA
# ---------------------------------------------------------
def test_seh_missing_table_rva():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"seh_count": 3, "seh_table_rva": None})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(i["issue"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID for i in issues)


# ---------------------------------------------------------
# 9. SEH out of range
# ---------------------------------------------------------
def test_seh_out_of_range():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"seh_count": 1000, "seh_table_rva": 0x1800})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(
        i["issue"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID
        and i["details"]["reason"] == "out_of_range"
        for i in issues
    )


# ---------------------------------------------------------
# 10. SEH unmapped
# ---------------------------------------------------------
def test_seh_unmapped():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"seh_count": 1, "seh_table_rva": 0x800})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(
        i["issue"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID
        and i["details"]["reason"] == "unmapped"
        for i in issues
    )


# ---------------------------------------------------------
# 11. SEH in overlay
# ---------------------------------------------------------
def test_seh_in_overlay():
    internal, metadata, analysis = _base()
    analysis["overlay_offset"] = 0x300
    analysis["load_config"].update({"seh_count": 1, "seh_table_rva": 0x1100})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert any(
        i["issue"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID
        and i["details"]["reason"] == "in_overlay"
        for i in issues
    )


# ---------------------------------------------------------
# 12. Fully valid → no issues
# ---------------------------------------------------------
def test_load_config_valid():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({
        "parsed_size": 0x80,
        "guard_cf_check_function_pointer": 0,
        "guard_cf_dispatch_function_pointer": 0,
        "guard_cf_function_table": 0,
        "guard_cf_function_count": 0,
        "security_cookie_rva": 0x1000,
        "seh_count": 0,
    })
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 13. Map RVA to Raw
# ---------------------------------------------------------
def test_map_rva_to_raw_section_missing():
    # section_ranges says there *should* be a section named ".missing"
    section_ranges = [(0x1000, 0x1200, ".missing")]

    # but sections list does NOT contain it
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x200, "raw_address": 0x400}
    ]

    # RVA falls inside the range → enters loop → sec lookup fails → FIRST return None
    result = _map_rva_to_raw(0x1000, sections, section_ranges)

    assert result is None


def test_map_rva_to_raw_no_matching_section():
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x200, "raw_address": 0x400}
    ]
    section_ranges = [(0x1000, 0x1200, ".text")]

    # RVA outside all section ranges
    result = _map_rva_to_raw(0x5000, sections, section_ranges)

    assert result is None


def test_map_rva_to_raw_missing_raw_address():
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x200}
        # raw_address missing
    ]
    section_ranges = [(0x1000, 0x1200, ".text")]

    result = _map_rva_to_raw(0x1000, sections, section_ranges)

    assert result is None


def test_validate_load_config_no_directory():
    internal = {"optional_header_magic": 0x10B}
    metadata = {"optional_header": {"size_of_image": 0x2000}}
    analysis = {
        "data_directories": [], # no load config entry
        "sections": [],
        "overlay_offset": None,
        "load_config": {},
    }

    issues = validate_load_config_directory(internal, metadata, analysis)

    assert issues == [] # early return


def test_validate_load_config_invalid_rva_or_size():
    internal = {"optional_header_magic": 0x10B}
    metadata = {"optional_header": {"size_of_image": 0x2000}}
    analysis = {
        "data_directories": [
            {"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": "not-int", "size": 0x100}
        ],
        "sections": [],
        "overlay_offset": None,
        "load_config": {},
    }

    issues = validate_load_config_directory(internal, metadata, analysis)

    assert issues == [] # early return
