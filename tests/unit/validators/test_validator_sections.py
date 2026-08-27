# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.sections import validate_sections
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]

def _has(issues, code, sub_reason=None):
    """True if an issue with `code` (and optionally `sub_reason`) was emitted."""
    return any(
        i["issue"] == code
        and (sub_reason is None or i["details"].get("sub_reason") == sub_reason)
        for i in issues
    )


# ---------------------------------------------------------
# 1) RWX section
# ---------------------------------------------------------

def test_section_rwx():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": ".text",
                # READ is set so the characteristics are inert scaffolding: EXECUTE without READ would additionally trip SECTION_FLAGS_INCONSISTENT/exec_without_read.
                "characteristics": 0x20000000 | 0x80000000 | 0x40000000,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_RWX in make_issue_list(issues)


# ---------------------------------------------------------
# 2) Code flag but not executable
# ---------------------------------------------------------

def test_section_non_executable_code_like():
    analysis = {"sections": [{
        # ".foo" avoids also tripping SECTION_CODELIKE_NAME_NOT_EXECUTABLE;
        # READ avoids SECTION_FLAGS_INCONSISTENT/code_without_read.
        "name": ".foo",
        "characteristics": 0x00000020 | 0x40000000,
    }]}
    issues = validate_sections({}, analysis)
    assert len(issues) == 1
    assert issues[0]["issue"] == ReasonCodes.SECTION_NON_EXECUTABLE_CODE_LIKE


# ---------------------------------------------------------
# 3) Code-like name but not executable
# ---------------------------------------------------------

def test_section_codelike_name_not_executable():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "text",
                "characteristics": 0x0, # not executable
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_CODELIKE_NAME_NOT_EXECUTABLE in make_issue_list(issues)


# ---------------------------------------------------------
# 4) Non-ASCII name
# ---------------------------------------------------------

def test_section_name_non_ascii():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "têxt", # non-ASCII
                "characteristics": 0x20000000 | 0x40000000,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_NAME_NON_ASCII in make_issue_list(issues)


def test_is_ascii_printable_typeerror_branch():
    class WeirdName:
        def __iter__(self):
            return iter([1, 2, 3]) # ord(1) → TypeError

        def strip(self):
            return self # allow .strip() to succeed

        def lower(self):
            return "not-code-like"

    metadata = {}
    analysis = {
        "sections": [
            {
                "name": WeirdName(),
                "characteristics": 0x40000000, # READ flag to avoid other issues
            }
        ]
    }

    issues = validate_sections(metadata, analysis)

    # Because _is_ascii_printable() returned False via TypeError,
    # we expect SECTION_NAME_NON_ASCII
    assert ReasonCodes.SECTION_NAME_NON_ASCII in make_issue_list(issues)

# ---------------------------------------------------------
# 5) Padding/empty name
# ---------------------------------------------------------

def test_section_name_padding():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "    ",
                "characteristics": 0x20000000 | 0x40000000,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_NAME_EMPTY_OR_PADDING in make_issue_list(issues)


# ---------------------------------------------------------
# 6) Impossible flag combinations (discardable + exec + write)
# ---------------------------------------------------------

def test_section_impossible_flags():
    # D+E+W necessarily also satisfies SECTION_RWX (E+W) and
    # SECTION_DISCARDABLE_CODE (D+E); the overlap is inherent to the condition,
    # so assert presence rather than an exact issue count. READ is set to
    # suppress the unrelated flags_inconsistent noise.
    analysis = {"sections": [{"name": ".x",
        "characteristics": 0x02000000 | 0x20000000 | 0x80000000 | 0x40000000}]}
    issues = validate_sections({}, analysis)
    assert _has(issues, ReasonCodes.SECTION_IMPOSSIBLE_FLAGS)


# ---------------------------------------------------------
# 7) Raw misalignment
# ---------------------------------------------------------

def test_section_raw_misaligned():
    metadata = {"optional_header": {"file_alignment": 512}}
    analysis = {
        "sections": [
            {
                "name": ".data",
                "characteristics": 0x20000000 | 0x40000000,
                "raw_address": 123, # not aligned
                "raw_size": 100,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_RAW_MISALIGNED in make_issue_list(issues)


# ---------------------------------------------------------
# 8) Section overlaps headers
# ---------------------------------------------------------

def test_section_overlaps_headers():
    metadata = {"optional_header": {"size_of_headers": 300}}
    analysis = {
        "sections": [
            {
                "name": ".data",
                "characteristics": 0x20000000 | 0x40000000,
                "raw_address": 100, # inside headers
                "raw_size": 100,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_OVERLAPS_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 9) Zero-length section
# ---------------------------------------------------------

def test_section_zero_length():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": ".empty",
                "characteristics": 0x20000000 | 0x40000000,
                "virtual_address": 1000,
                "virtual_size": 0,
                "raw_address": 2000,
                "raw_size": 0,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_ZERO_LENGTH in make_issue_list(issues)


# ---------------------------------------------------------
# 10) Discardable + executable (even without write)
# ---------------------------------------------------------

def test_section_discardable_code():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": ".text",
                 # DISCARDABLE | EXECUTE is the anomaly; READ is added so the
                 # fixture doesn't also trip SECTION_FLAGS_INCONSISTENT/
                 # exec_without_read.
                "characteristics": 0x02000000 | 0x20000000 | 0x40000000,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_DISCARDABLE_CODE in make_issue_list(issues)


# ---------------------------------------------------------
# 11) Contradictory flags
# ---------------------------------------------------------

def test_section_flags_inconsistent_code_without_read():
    # ".foo" avoids the code-like-name check; CNT_CODE without READ is the
    # anomaly. SECTION_NON_EXECUTABLE_CODE_LIKE also fires - inherent, since
    # CNT_CODE without EXECUTE is exactly that condition.
    analysis = {"sections": [{"name": ".foo", "characteristics": 0x00000020}]}
    issues = validate_sections({}, analysis)
    assert _has(issues, ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                "code_without_read")


def test_section_flags_inconsistent_write_without_read():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": ".data",
                "characteristics": 0x80000000, # WRITE but no READ
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert _has(issues, ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                "write_without_read")


def test_section_flags_inconsistent_exec_without_read():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": ".text",
                "characteristics": 0x20000000, # EXEC but no READ
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert _has(issues, ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                "exec_without_read")


# ---------------------------------------------------------
# 12) Raw overlap detection
# ---------------------------------------------------------

def test_section_raw_overlap():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "A",
                "characteristics": 0x20000000,
                "raw_address": 100,
                "raw_size": 100,
            },
            {
                "name": "B",
                "characteristics": 0x20000000,
                "raw_address": 150, # overlaps A
                "raw_size": 100,
            },
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_RAW_OVERLAP in make_issue_list(issues)


def test_section_raw_overlap_inner_continue():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "A",
                "characteristics": 0x40000000, # READ
                "raw_address": 100,
                "raw_size": 50,
            },
            {
                "name": "B",
                "characteristics": 0x40000000,
                "raw_address": "not-an-int", # triggers inner continue
                "raw_size": 50,
            },
        ]
    }

    issues = validate_sections(metadata, analysis)

    # No overlap issues should be produced because the inner loop continues
    assert ReasonCodes.SECTION_RAW_OVERLAP not in make_issue_list(issues)

# ---------------------------------------------------------
# 13) Virtual overlap detection
# ---------------------------------------------------------

def test_section_virtual_overlap():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "A",
                "characteristics": 0x20000000,
                "virtual_address": 1000,
                "virtual_size": 200,
            },
            {
                "name": "B",
                "characteristics": 0x20000000,
                "virtual_address": 1100, # overlaps A
                "virtual_size": 200,
            },
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_OVERLAP in make_issue_list(issues)


def test_section_virtual_overlap_inner_continue():
    metadata = {}
    analysis = {
        "sections": [
            {
                "name": "A",
                "characteristics": 0x40000000, # READ
                "virtual_address": 1000,
                "virtual_size": 100,
            },
            {
                "name": "B",
                "characteristics": 0x40000000,
                "virtual_address": "not-an-int", # triggers inner continue
                "virtual_size": 200,
            },
        ]
    }

    issues = validate_sections(metadata, analysis)

    # No virtual overlap issue should be produced because the inner loop continues
    assert ReasonCodes.SECTION_OVERLAP not in make_issue_list(issues)


# ---------------------------------------------------------
# 14) Raw ordering
# ---------------------------------------------------------

def test_section_out_of_order_raw():
    metadata = {}
    analysis = {
        "sections": [
            {"name": "A", "characteristics": 0x20000000, "raw_address": 300},
            {"name": "B", "characteristics": 0x20000000, "raw_address": 100},
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_OUT_OF_ORDER_RAW in make_issue_list(issues)


# ---------------------------------------------------------
# 15) Virtual ordering
# ---------------------------------------------------------

def test_section_out_of_order_virtual():
    metadata = {}
    analysis = {
        "sections": [
            {"name": "A", "characteristics": 0x20000000, "virtual_address": 300},
            {"name": "B", "characteristics": 0x20000000, "virtual_address": 100},
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert ReasonCodes.SECTION_OUT_OF_ORDER_VIRTUAL in make_issue_list(issues)


# ---------------------------------------------------------
# 16) Clean case
# ---------------------------------------------------------

def test_section_valid_no_issues():
    metadata = {"optional_header": {"file_alignment": 512, "size_of_headers": 100}}
    analysis = {
        "sections": [
            {
                "name": ".text",
                "characteristics": 0x20000000 | 0x40000000, # exec + read
                "raw_address": 512,
                "raw_size": 100,
                "virtual_address": 0x1000,
                "virtual_size": 100,
            }
        ]
    }
    issues = validate_sections(metadata, analysis)
    assert issues == []


# --------------------------------------------------------------------
# 17) Contract and reason key tests
# --------------------------------------------------------------------

def test_dependency_contract():
    assert getattr(validate_sections, "_depends_on") == ("metadata", "analysis")


def test_no_details_payload_uses_reserved_reason_key():
    """
    "reason" is reserved by the heuristics emission layer: _det builds metadata
    as {"reason": parent, **details}, so a details["reason"] would overwrite
    the parent reason code. Validators must use "sub_reason".

    CNT_CODE|WRITE|EXECUTE without READ trips all three sub_reason sites.
    """
    analysis = {"sections": [{"name": ".foo",
        "characteristics": 0x00000020 | 0x80000000 | 0x20000000}]}
    issues = validate_sections({}, analysis)
    assert issues, "fixture should produce issues"
    offenders = [i["issue"] for i in issues if "reason" in i["details"]]
    assert not offenders, (
        f"details payload used the reserved key 'reason' for: {offenders}"
    )

