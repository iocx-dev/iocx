# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.load_config_directory.

Layer note: the validator is @depends_on("internal", "metadata", "analysis")
and takes THREE positional arguments. SizeOfImage is read from
metadata["optional_header"]["size_of_image"].

Details note: sub-reasons are carried in a "sub_reason" key. The key "reason"
is reserved by the heuristics emission layer, which merges details over its own
reason field - a details["reason"] would overwrite the parent reason code.

AMBIGUITY CAUTION: this validator shares sub-reason strings across two parent
codes - "unmapped" is emitted by BOTH LOAD_CONFIG_COOKIE_INVALID and
LOAD_CONFIG_SEH_INVALID. Asserting on the sub-reason alone is therefore not
sufficient to identify which check fired; always pair it with the parent code
(as the `any(... and ...)` assertions below do). Under the reason collision the
parent was overwritten and these two were indistinguishable in output.
"""

import pytest
from iocx.validators.load_config_directory import validate_load_config_directory, _map_rva_to_raw
from iocx.reason_codes import ReasonCodes


def _base():
    """Return minimal valid metadata structures."""
    internal = {"optional_header_magic": 0x10B}  # PE32
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
                "characteristics": 0x80000000,  # writable
            }
        ],
        "overlay_offset": None,
        "load_config": {},
    }
    return internal, metadata, analysis


def _has(issues, code, sub_reason=None):
    """True if an issue with `code` (and optionally `sub_reason`) was emitted."""
    return any(
        i["issue"] == code
        and (sub_reason is None or i["details"].get("sub_reason") == sub_reason)
        for i in issues
    )


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
    analysis["data_directories"][0]["size"] = 0x20  # < 0x48
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
    analysis["load_config"]["security_cookie_rva"] = 0x5000  # outside section
    issues = validate_load_config_directory(internal, metadata, analysis)
    # Pair code + sub_reason: "unmapped" is also emitted by SEH_INVALID, so the
    # code alone would not distinguish which check fired.
    assert _has(issues, ReasonCodes.LOAD_CONFIG_COOKIE_INVALID, "unmapped")


# ---------------------------------------------------------
# 6. Cookie in non-writable section
# ---------------------------------------------------------
def test_cookie_non_writable():
    internal, metadata, analysis = _base()
    analysis["sections"][0]["characteristics"] = 0  # not writable
    analysis["load_config"]["security_cookie_rva"] = 0x1000
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert _has(issues, ReasonCodes.LOAD_CONFIG_COOKIE_INVALID,
                "non_writable_section")


# ---------------------------------------------------------
# 7. Cookie in overlay
# ---------------------------------------------------------
def test_cookie_in_overlay():
    internal, metadata, analysis = _base()
    analysis["overlay_offset"] = 0x300  # raw offset threshold
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
    # SEH_INVALID has four distinct sub-reasons; pin which one fired.
    assert _has(issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "missing_table_rva")


# ---------------------------------------------------------
# 9. SEH out of range
# ---------------------------------------------------------
def test_seh_out_of_range():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"seh_count": 1000, "seh_table_rva": 0x1800})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert _has(issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "out_of_range")


# ---------------------------------------------------------
# 10. SEH unmapped
# ---------------------------------------------------------
def test_seh_unmapped():
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"seh_count": 1, "seh_table_rva": 0x800})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert _has(issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "unmapped")


# ---------------------------------------------------------
# 11. SEH in overlay
# ---------------------------------------------------------
def test_seh_in_overlay():
    internal, metadata, analysis = _base()
    analysis["overlay_offset"] = 0x300
    analysis["load_config"].update({"seh_count": 1, "seh_table_rva": 0x1100})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert _has(issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "in_overlay")


# ---------------------------------------------------------
# 11b. The shared "unmapped" string is disambiguated by its parent
# ---------------------------------------------------------
def test_shared_unmapped_substring_is_disambiguated_by_parent():
    """
    "unmapped" is emitted by BOTH LOAD_CONFIG_COOKIE_INVALID and
    LOAD_CONFIG_SEH_INVALID. The parent code is what separates them.

    This is precisely the ambiguity the reason collision created: with the
    parent overwritten, a consumer saw the bare string "unmapped" and could
    not tell a security-cookie fault from an SEH-table fault.
    """
    # cookie unmapped, SEH clean
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"security_cookie_rva": 0x5000, "seh_count": 0})
    cookie_issues = validate_load_config_directory(internal, metadata, analysis)

    # SEH unmapped, cookie clean
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"security_cookie_rva": 0x1000,
                                    "seh_count": 1, "seh_table_rva": 0x800})
    seh_issues = validate_load_config_directory(internal, metadata, analysis)

    assert _has(cookie_issues, ReasonCodes.LOAD_CONFIG_COOKIE_INVALID, "unmapped")
    assert not _has(cookie_issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "unmapped")

    assert _has(seh_issues, ReasonCodes.LOAD_CONFIG_SEH_INVALID, "unmapped")
    assert not _has(seh_issues, ReasonCodes.LOAD_CONFIG_COOKIE_INVALID, "unmapped")


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
        "data_directories": [],  # no load config entry
        "sections": [],
        "overlay_offset": None,
        "load_config": {},
    }

    issues = validate_load_config_directory(internal, metadata, analysis)

    assert issues == []  # early return


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

    assert issues == []  # early return


# ---------------------------------------------------------
# 14. Output contract
# ---------------------------------------------------------
def test_dependency_contract():
    assert getattr(validate_load_config_directory, "_depends_on") == (
        "internal", "metadata", "analysis")


def test_no_details_payload_uses_reserved_reason_key():
    """
    "reason" is reserved by the heuristics emission layer: _det builds metadata
    as {"reason": parent, **details}, so a details["reason"] would overwrite
    the parent reason code. Validators must use "sub_reason".

    Exercises the too-small, truncated, guard-CF, cookie and SEH paths together.
    """
    internal, metadata, analysis = _base()
    analysis["data_directories"][0]["size"] = 0x20      # too small
    analysis["sections"][0]["characteristics"] = 0       # cookie non-writable
    analysis["load_config"].update({
        "parsed_size": 0x10,                             # truncated
        "guard_cf_check_function_pointer": 0x1234,       # guard CF inconsistent
        "guard_cf_function_count": 0,
        "security_cookie_rva": 0x1000,
        "seh_count": 1000, "seh_table_rva": 0x1800,      # SEH out of range
    })
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert issues, "fixture should produce issues"
    offenders = [i["issue"] for i in issues if "reason" in i["details"]]
    assert not offenders, (
        f"details payload used the reserved key 'reason' for: {offenders}"
    )


def test_unmapped_paths_avoid_reserved_reason_key():
    """The two 'unmapped' branches are mutually exclusive with the above."""
    internal, metadata, analysis = _base()
    analysis["load_config"].update({"security_cookie_rva": 0x5000,
                                    "seh_count": 1, "seh_table_rva": 0x800})
    issues = validate_load_config_directory(internal, metadata, analysis)
    assert issues
    assert all("reason" not in i["details"] for i in issues)


# ---------------------------------------------------------
# 15. Determinism
# ---------------------------------------------------------
def test_repeated_calls_identical():
    import json
    internal, metadata, analysis = _base()
    analysis["sections"][0]["characteristics"] = 0
    analysis["overlay_offset"] = 0x300
    analysis["load_config"].update({
        "parsed_size": 0x10,
        "guard_cf_check_function_pointer": 0x1234,
        "guard_cf_function_count": 0,
        "security_cookie_rva": 0x1100,
        "seh_count": 1, "seh_table_rva": 0x1100,
    })
    a = validate_load_config_directory(internal, metadata, analysis)
    b = validate_load_config_directory(internal, metadata, analysis)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
