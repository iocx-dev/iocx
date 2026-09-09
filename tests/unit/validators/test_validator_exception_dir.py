# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.exception_table.validate_exception_table.

Strategy:
- Input is the exception_struct dict produced by parser pe_exception, carried
  under internal["exception_struct"].
- Build dicts directly to isolate validator logic from parser behaviour.
- Tests assert on emitted REASONCODES and the details payload.

Layer note: the validator is @depends_on("internal", "metadata") and takes TWO
positional arguments. SizeOfImage is read from
metadata["optional_header"]["size_of_image"] - it is NOT part of the analysis
layer, and the validator never receives one.

Details note: priority-resolved sub-reasons are carried in a "sub_reason" key.
The key "reason" is reserved by the heuristics emission layer, which merges
details over its own reason field - a details["reason"] would overwrite the
parent reason code.

Fixture note: every fixture below has been verified to emit exactly ONE issue
(or none, for controls) unless a multi-issue outcome is asserted deliberately.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.exception_table import validate_exception_table


SIZE_OF_IMAGE = 0x5000


# =================================================================
# Input builders
# =================================================================

def _make_metadata(size_of_image: Optional[int] = SIZE_OF_IMAGE) -> Dict[str, Any]:
    """
    Public-metadata layer. SizeOfImage lives under optional_header; passing
    None models an optional header present but missing the field.
    """
    return {"optional_header": {"size_of_image": size_of_image}}


def _make_unwind(
    version: Optional[int] = 1,
    flags: Optional[int] = 0,
    size_of_prolog: Optional[int] = 4,
    count_of_codes: Optional[int] = 0,
    is_chained: bool = False,
    chained_rva: Optional[int] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """AMD64 UNWIND_INFO sub-dict. Defaults are a clean V1 record."""
    return {
        "version": version,
        "flags": flags,
        "size_of_prolog": size_of_prolog,
        "count_of_codes": count_of_codes,
        "is_chained": is_chained,
        "chained_rva": chained_rva,
        "errors": errors or [],
    }


def _make_entry(
    index: int = 0,
    begin_rva: Optional[int] = 0x1000,
    end_rva: Optional[int] = 0x1050,
    unwind_info_rva: Optional[int] = 0x4100,
    unwind: Any = "DEFAULT",
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """AMD64 RUNTIME_FUNCTION entry. `unwind="DEFAULT"` builds a clean record."""
    return {
        "index": index,
        "begin_rva": begin_rva,
        "end_rva": end_rva,
        "unwind_info_rva": unwind_info_rva,
        "unwind": _make_unwind() if unwind == "DEFAULT" else unwind,
        "errors": errors or [],
    }


def _make_arm_entry(
    index: int = 0,
    begin_rva: Optional[int] = 0x1500,
    unwind_info_rva: Optional[int] = 0x4100,
    is_packed: bool = False,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    ARM/ARM64 8-byte record. Carries NO EndAddress, so end_rva is None and the
    validator's range/overlap checks correctly no-op. Packed records carry no
    .xdata pointer.
    """
    return {
        "index": index,
        "begin_rva": begin_rva,
        "end_rva": None,
        "unwind_info_rva": None if is_packed else unwind_info_rva,
        "unwind": None,
        "is_packed": is_packed,
        "packed_data": 0x0AB10001 if is_packed else None,
        "errors": errors or [],
    }


def _make_ex(
    rva: Optional[int] = 0x4000,
    size: int = 24,
    machine: Optional[int] = 0x8664,
    arch: str = "amd64",
    entry_size: int = 12,
    functions: Optional[List[Dict[str, Any]]] = None,
    truncations: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "rva": rva,
        "size": size,
        "machine": machine,
        "arch": arch,
        "entry_size": entry_size,
        "functions": functions or [],
        "truncations": truncations or [],
        "errors": errors or [],
    }


def _control_functions() -> List[Dict[str, Any]]:
    """Two sorted, non-overlapping, in-bounds entries with clean unwind info."""
    return [
        _make_entry(0, 0x1000, 0x1050, 0x4100),
        _make_entry(1, 0x1060, 0x10B0, 0x4110),
    ]


def _run(ex: Optional[Dict[str, Any]],
         metadata: Optional[Dict[str, Any]] = None):
    if metadata is None:
        metadata = _make_metadata()
    return validate_exception_table({"exception_struct": ex}, metadata)


def _codes(issues) -> List:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


def _has(issues, code, sub_reason=None) -> bool:
    """True if an issue with `code` (and optionally `sub_reason`) was emitted."""
    return any(
        i["issue"] == code
        and (sub_reason is None or i["details"].get("sub_reason") == sub_reason)
        for i in issues
    )


# =================================================================
# Absence
# =================================================================

class TestAbsence:
    """Absence of an exception directory is never a structural defect."""

    def test_no_exception_struct_returns_no_issues(self):
        assert validate_exception_table({}, _make_metadata()) == []

    def test_explicit_none_returns_no_issues(self):
        assert _run(None) == []


# =================================================================
# Controls
# =================================================================

class TestControls:
    """Well-formed tables emit nothing. These anchor every anomaly below."""

    def test_amd64_control_emits_nothing(self):
        assert _run(_make_ex(functions=_control_functions())) == []

    def test_arm64_xdata_control_emits_nothing(self):
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1500),
                                 _make_arm_entry(1, 0x1600)])
        assert _run(ex) == []

    def test_arm64_packed_control_emits_nothing(self):
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1500, is_packed=True),
                                 _make_arm_entry(1, 0x1600, is_packed=True)])
        assert _run(ex) == []

    def test_arm64ec_control_emits_nothing(self):
        """ARM64EC (0xA641) routes through the same arm64 walk."""
        ex = _make_ex(machine=0xA641, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1500),
                                 _make_arm_entry(1, 0x1600)])
        assert _run(ex) == []


# =================================================================
# Top-level decode short-circuit
# =================================================================

class TestTopLevelDecodeFailure:

    def test_errors_emit_invalid_header(self):
        ex = _make_ex(errors=["directory_read_failed"])
        issues = _run(ex)
        assert _codes(issues) == [ReasonCodes.EXCEPTION_DIRECTORY_INVALID_HEADER]
        d = _details_for(issues, ReasonCodes.EXCEPTION_DIRECTORY_INVALID_HEADER)[0]
        assert d["sub_reason"] == "top_level_decode"
        assert d["errors"] == ["directory_read_failed"]

    def test_short_circuit_skips_all_later_checks(self):
        """
        A top-level error must suppress directory, truncation, arch and
        function-table checks - every one of which this fixture would
        otherwise trip.
        """
        ex = _make_ex(
            rva=0x4001,                       # would trip UNALIGNED
            size=25,                          # would trip SIZE_NOT_MULTIPLE
            errors=["boom"],
            truncations=["exception_entry_truncated"],
            functions=[_make_entry(0, 0, 0x1050, 0x4100,
                                   errors=["begin_rva_zero"])],
        )
        issues = _run(ex)
        assert _codes(issues) == [ReasonCodes.EXCEPTION_DIRECTORY_INVALID_HEADER]


# =================================================================
# Directory-level checks
# =================================================================

class TestDirectoryPlacement:

    def test_unaligned_directory_rva_flagged(self):
        ex = _make_ex(rva=0x4001, functions=_control_functions())
        issues = _run(ex)
        assert len(issues) == 1
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_DIRECTORY_UNALIGNED
        assert issues[0]["details"]["rva"] == 0x4001
        assert issues[0]["details"]["alignment"] == 4

    def test_aligned_directory_rva_not_flagged(self):
        ex = _make_ex(rva=0x4000, functions=_control_functions())
        assert ReasonCodes.EXCEPTION_DIRECTORY_UNALIGNED not in _codes(_run(ex))

    def test_size_not_multiple_of_entry_stride_flagged(self):
        ex = _make_ex(size=25, functions=_control_functions())
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE
        assert d["entry_size"] == 12
        assert d["remainder"] == 1

    def test_size_multiple_of_stride_not_flagged(self):
        ex = _make_ex(size=24, functions=_control_functions())
        assert ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE not in _codes(_run(ex))

    def test_arm_stride_of_eight_respected(self):
        """A size of 16 is valid for arm (stride 8) though not for amd64."""
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1500)])
        assert ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE not in _codes(_run(ex))

    def test_directory_out_of_bounds_flagged(self):
        # rva 0x4FF8 + size 12 = 0x5004 > SizeOfImage 0x5000
        ex = _make_ex(rva=0x4FF8, size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0x4100)])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_DIRECTORY_OUT_OF_BOUNDS
        assert d["rva"] == 0x4FF8
        assert d["size_of_image"] == SIZE_OF_IMAGE

    def test_directory_exactly_at_boundary_not_flagged(self):
        # rva + size == SizeOfImage is inclusive
        ex = _make_ex(rva=0x4FF4, size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0x4100)])
        assert ReasonCodes.EXCEPTION_DIRECTORY_OUT_OF_BOUNDS not in _codes(_run(ex))

    def test_rva_none_skips_directory_checks(self):
        ex = _make_ex(rva=None, size=25, functions=[])
        issues = _run(ex)
        assert ReasonCodes.EXCEPTION_DIRECTORY_UNALIGNED not in _codes(issues)
        assert ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE not in _codes(issues)
        assert issues == []


# =================================================================
# Layer sourcing (SizeOfImage)
# =================================================================

class TestSizeOfImageLayer:
    """
    SizeOfImage must be read from metadata["optional_header"]. Reading it from
    the analysis layer - where it does not exist - silently disabled every
    bounds check in production while unit tests that supplied it there passed.
    """

    def test_out_of_bounds_fires_with_metadata_layer(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x99000, 0x99050, 0x4100)])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS)

    def test_size_of_image_at_top_level_is_ignored(self):
        """
        REGRESSION GUARD. A stale analysis-shaped dict must NOT be consulted;
        if it were, the bounds check would fire and the production dead-path
        would be back.
        """
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x99000, 0x99050, 0x4100)])
        issues = _run(ex, metadata={"size_of_image": SIZE_OF_IMAGE})
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS not in _codes(issues)

    def test_absent_optional_header_skips_bounds_checks(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x99000, 0x99050, 0x4100)])
        issues = _run(ex, metadata={})
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS not in _codes(issues)
        assert ReasonCodes.EXCEPTION_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_none_size_of_image_skips_bounds_checks(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x99000, 0x99050, 0x4100)])
        issues = _run(ex, metadata=_make_metadata(size_of_image=None))
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS not in _codes(issues)


# =================================================================
# Truncations
# =================================================================

class TestTruncations:

    def test_single_tag_emits_one_issue(self):
        ex = _make_ex(truncations=["exception_entry_truncated"],
                      functions=_control_functions())
        issues = _run(ex)
        assert len(issues) == 1
        # "table" is a distinct key and was never subject to the reason
        # collision, so it is unchanged by the sub_reason migration.
        assert issues[0]["details"] == {"table": "exception_entry_truncated"}

    def test_multiple_tags_emit_one_issue_each_in_order(self):
        ex = _make_ex(truncations=["exception_table_ragged_tail",
                                   "exception_entry_read_failed"],
                      functions=_control_functions())
        issues = _run(ex)
        tables = [d["table"] for d in
                  _details_for(issues, ReasonCodes.EXCEPTION_TABLE_TRUNCATED)]
        assert tables == ["exception_table_ragged_tail",
                          "exception_entry_read_failed"]

    def test_no_truncations_emits_nothing(self):
        ex = _make_ex(truncations=[], functions=_control_functions())
        assert ReasonCodes.EXCEPTION_TABLE_TRUNCATED not in _codes(_run(ex))


# =================================================================
# Architecture gate
# =================================================================

class TestArchitectureGate:

    def test_unsupported_machine_reported_once(self):
        ex = _make_ex(machine=0x014C, arch="unsupported", entry_size=0,
                      functions=[])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_UNSUPPORTED_MACHINE
        assert d["arch"] == "unsupported"
        assert d["machine"] == 0x014C

    def test_unsupported_machine_skips_function_walk(self):
        """
        The walk must be skipped rather than producing spurious per-entry
        codes on a directory we cannot interpret.
        """
        ex = _make_ex(machine=0x014C, arch="unsupported", entry_size=0,
                      functions=[_make_entry(0, 0, 0x1050, 0x4100,
                                             errors=["begin_rva_zero"])])
        issues = _run(ex)
        assert _codes(issues) == [ReasonCodes.EXCEPTION_UNSUPPORTED_MACHINE]

    @pytest.mark.parametrize("machine,arch", [
        (0x8664, "amd64"),
        (0xAA64, "arm64"),
        (0xA641, "arm64"),   # ARM64EC
        (0x01C4, "arm"),     # ARMNT
    ])
    def test_table_archs_are_walked(self, machine, arch):
        """Every table-based arch reaches the function walk."""
        entry_size = 12 if arch == "amd64" else 8
        if arch == "amd64":
            funcs = [_make_entry(0, 0x1900, 0x1950, 0x4100),
                     _make_entry(1, 0x1800, 0x1850, 0x4110)]
            size = 24
        else:
            funcs = [_make_arm_entry(0, 0x1900), _make_arm_entry(1, 0x1800)]
            size = 16
        ex = _make_ex(machine=machine, arch=arch, entry_size=entry_size,
                      size=size, functions=funcs)
        assert _has(_run(ex), ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED)


# =================================================================
# Per-entry parser errors
# =================================================================

class TestEntryInvalid:

    def test_begin_rva_zero_flagged(self):
        ex = _make_ex(functions=[
            _make_entry(0, 0x1000, 0x1050, 0x4100),
            _make_entry(1, 0, 0x10B0, 0x4110, errors=["begin_rva_zero"]),
        ])
        issues = _run(ex)
        assert len(issues) == 1
        assert _has(issues, ReasonCodes.EXCEPTION_ENTRY_INVALID, "begin_rva_zero")
        assert _details_for(issues, ReasonCodes.EXCEPTION_ENTRY_INVALID)[0]["index"] == 1

    @pytest.mark.parametrize("tag", [
        "entry_unpack_failed",
        "begin_rva_zero", "end_rva_zero", "unwind_rva_zero",
    ])
    def test_each_priority_tag_resolves(self, tag):
        ex = _make_ex(size=12, functions=[
            _make_entry(0, None, None, None, unwind=None, errors=[tag])])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_ENTRY_INVALID, tag)

    def test_priority_first_match_wins(self):
        """entry_truncated outranks begin_rva_zero and unwind_rva_zero."""
        ex = _make_ex(size=12, functions=[_make_entry(
            0, None, None, None, unwind=None,
            errors=["begin_rva_zero", "unwind_rva_zero"])])
        issues = _run(ex)
        assert len(issues) == 1
        assert _has(issues, ReasonCodes.EXCEPTION_ENTRY_INVALID, "begin_rva_zero")

    def test_unknown_tag_not_flagged(self):
        """A future parser tag not in the priority list is skipped silently."""
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100, errors=["future_tag_not_recognised"])])
        assert ReasonCodes.EXCEPTION_ENTRY_INVALID not in _codes(_run(ex))

    def test_invalid_entry_skips_cross_entry_checks(self):
        """
        A structurally unreadable entry cannot feed sortedness/overlap, so it
        is skipped rather than producing misleading follow-on codes.
        """
        ex = _make_ex(functions=[
            _make_entry(0, 0x1900, 0x1950, 0x4100),
            # begin 0 would look "unsorted" against 0x1900 if not skipped
            _make_entry(1, 0, 0x1850, 0x4110, errors=["begin_rva_zero"]),
        ])
        issues = _run(ex)
        assert _codes(issues) == [ReasonCodes.EXCEPTION_ENTRY_INVALID]

    def test_multiple_bad_entries_each_flagged(self):
        ex = _make_ex(size=36, functions=[
            _make_entry(0, 0x1000, 0x1050, 0x4100),
            _make_entry(1, 0, 0x10B0, 0x4110, errors=["begin_rva_zero"]),
            _make_entry(2, 0x10C0, 0, 0x4120, errors=["end_rva_zero"]),
        ])
        assert len(_details_for(_run(ex), ReasonCodes.EXCEPTION_ENTRY_INVALID)) == 2


# =================================================================
# Function range
# =================================================================

class TestFunctionRange:

    def test_begin_equals_end_flagged_as_empty(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1500, 0x1500, 0x4100)])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID
        assert d["empty"] is True

    def test_begin_greater_than_end_flagged_as_inverted(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1500, 0x1400, 0x4100)])
        issues = _run(ex)
        assert _has(issues, ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID)
        d = _details_for(issues, ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID)[0]
        assert d["empty"] is False

    def test_valid_range_not_flagged(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0x4100)])
        assert ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID not in _codes(_run(ex))

    def test_arm_entries_skip_range_check(self):
        """ARM records carry no EndAddress, so the check must no-op."""
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=8,
                      functions=[_make_arm_entry(0, 0x1500)])
        assert ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID not in _codes(_run(ex))


# =================================================================
# RVA bounds
# =================================================================

class TestFunctionRvaBounds:

    def test_begin_and_end_out_of_bounds_listed_in_fields(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x99000, 0x99050, 0x4100)])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS
        # "fields" is a distinct key naming each offending RVA
        assert d["fields"] == ["begin_rva", "end_rva"]
        assert d["size_of_image"] == SIZE_OF_IMAGE

    def test_unwind_rva_out_of_bounds_listed(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0x99000,
                                             unwind=None)])
        d = _details_for(_run(ex),
                         ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS)[0]
        assert d["fields"] == ["unwind_info_rva"]

    def test_zero_unwind_rva_not_bounds_checked(self):
        """UnwindInfoAddress of 0 is absent, not out of bounds."""
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0,
                                             unwind=None)])
        issues = _run(ex)
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS not in _codes(issues)

    def test_end_rva_may_equal_size_of_image(self):
        """
        EndAddress is one past the function, so end == SizeOfImage is legal
        while begin == SizeOfImage is not.
        """
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x4FF0, SIZE_OF_IMAGE, 0x4100)])
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS not in _codes(_run(ex))

    def test_begin_at_size_of_image_flagged(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, SIZE_OF_IMAGE, SIZE_OF_IMAGE,
                                             0x4100)])
        d = _details_for(_run(ex),
                         ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS)[0]
        assert "begin_rva" in d["fields"]


# =================================================================
# Sortedness — the headline heuristic
# =================================================================

class TestSortedness:
    """
    The loader binary-searches .pdata, so BeginAddress must ascend. An
    out-of-order entry silently loses its unwind data at runtime while every
    byte is present on disk.
    """

    def test_descending_begin_flagged(self):
        ex = _make_ex(functions=[
            _make_entry(0, 0x1900, 0x1950, 0x4100),
            _make_entry(1, 0x1800, 0x1850, 0x4110),
        ])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED
        assert d["begin_rva"] == 0x1800
        assert d["prev_begin_rva"] == 0x1900
        assert d["index"] == 1

    def test_ascending_begin_not_flagged(self):
        assert ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED not in _codes(
            _run(_make_ex(functions=_control_functions())))

    def test_equal_begin_not_flagged(self):
        """Ascending is non-strict; equal begins are an overlap, not disorder."""
        ex = _make_ex(functions=[
            _make_entry(0, 0x1000, 0x1050, 0x4100),
            _make_entry(1, 0x1000, 0x1050, 0x4110),
        ])
        assert ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED not in _codes(_run(ex))

    def test_wild_entry_does_not_poison_the_cursor(self):
        """
        The ascending cursor only advances on sane, sorted begins, so a single
        out-of-order entry must not lower the bar for everything after it.

        Entry 2 is chosen to sit BETWEEN the wild value (0x0900) and the true
        cursor (0x1000). A correct cursor still holds 0x1000, so entry 2 is
        also unsorted -> 2 issues. A cursor that advanced onto the wild entry
        would hold 0x0900, making entry 2 look fine -> 1 issue. A fixture
        above both values (e.g. 0x1100) cannot tell the two apart.
        """
        ex = _make_ex(size=36, functions=[
            _make_entry(0, 0x1000, 0x1050, 0x4100),
            _make_entry(1, 0x0900, 0x0950, 0x4110),   # the wild one
            _make_entry(2, 0x0950, 0x0990, 0x4120),   # between wild and cursor
        ])
        issues = _run(ex)
        not_sorted = _details_for(issues, ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED)
        assert len(not_sorted) == 2
        assert [d["index"] for d in not_sorted] == [1, 2]
        # both compared against the UNMOVED cursor, not the wild entry
        assert all(d["prev_begin_rva"] == 0x1000 for d in not_sorted)

    def test_sortedness_applies_to_arm(self):
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1600),
                                 _make_arm_entry(1, 0x1500)])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED)

    def test_sortedness_applies_to_arm_packed(self):
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1600, is_packed=True),
                                 _make_arm_entry(1, 0x1500, is_packed=True)])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED)

    def test_sortedness_applies_to_arm64ec(self):
        """ARM64EC uses the same walk, so the invariant holds there too."""
        ex = _make_ex(machine=0xA641, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1600),
                                 _make_arm_entry(1, 0x1500)])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED)


# =================================================================
# Overlap
# =================================================================

class TestFunctionOverlap:

    def test_overlapping_ranges_flagged(self):
        ex = _make_ex(functions=[
            _make_entry(0, 0x1800, 0x1880, 0x4100),
            _make_entry(1, 0x1840, 0x18C0, 0x4110),   # begins inside entry 0
        ])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_FUNCTION_OVERLAP
        assert d["begin_rva"] == 0x1840
        assert d["prev_end_rva"] == 0x1880

    def test_adjacent_ranges_not_flagged(self):
        """prev_end is exclusive: begin == prev_end is adjacency, not overlap."""
        ex = _make_ex(functions=[
            _make_entry(0, 0x1000, 0x1050, 0x4100),
            _make_entry(1, 0x1050, 0x10A0, 0x4110),
        ])
        assert ReasonCodes.EXCEPTION_FUNCTION_OVERLAP not in _codes(_run(ex))

    def test_unsorted_pair_not_double_counted_as_overlap(self):
        """
        An unsorted pair is reported once as NOT_SORTED; the overlap check is
        gated on begin >= prev_begin so it does not also fire.
        """
        ex = _make_ex(functions=[
            _make_entry(0, 0x1900, 0x1950, 0x4100),
            _make_entry(1, 0x1800, 0x1850, 0x4110),
        ])
        issues = _run(ex)
        assert ReasonCodes.EXCEPTION_FUNCTION_OVERLAP not in _codes(issues)
        assert _codes(issues) == [ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED]

    def test_arm_entries_skip_overlap_check(self):
        """No EndAddress means no overlap can be computed."""
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=16,
                      functions=[_make_arm_entry(0, 0x1800),
                                 _make_arm_entry(1, 0x1840)])
        assert _run(ex) == []


# =================================================================
# Unwind info (AMD64)
# =================================================================

class TestUnwindInfo:

    def test_unaligned_unwind_rva_flagged(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0x4101)])
        issues = _run(ex)
        assert len(issues) == 1
        d = issues[0]["details"]
        assert issues[0]["issue"] == ReasonCodes.EXCEPTION_UNWIND_INFO_UNALIGNED
        assert d["unwind_info_rva"] == 0x4101
        assert d["alignment"] == 4

    def test_zero_unwind_rva_not_alignment_checked(self):
        ex = _make_ex(size=12,
                      functions=[_make_entry(0, 0x1000, 0x1050, 0,
                                             unwind=None)])
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_UNALIGNED not in _codes(_run(ex))

    @pytest.mark.parametrize("version", [1, 2, 3])
    def test_valid_versions_not_flagged(self, version):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100, unwind=_make_unwind(version=version))])
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID not in _codes(_run(ex))

    @pytest.mark.parametrize("version", [0, 4, 5, 7])
    def test_invalid_versions_flagged(self, version):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100, unwind=_make_unwind(version=version))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID,
                    "unwind_version_invalid")

    @pytest.mark.parametrize("flags", [0x00, 0x01, 0x02, 0x04, 0x08, 0x0F])
    def test_known_flag_bits_not_flagged(self, flags):
        """EHANDLER | UHANDLER | CHAININFO | LARGE are all legal."""
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            # a chained blob needs a valid target, else the chain check fires
            unwind=_make_unwind(flags=flags, chained_rva=0x4200))])
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID not in _codes(_run(ex))

    @pytest.mark.parametrize("flags", [0x10, 0x20, 0x80])
    def test_reserved_flag_bits_flagged(self, flags):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100, unwind=_make_unwind(flags=flags))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID,
                    "unwind_flags_reserved_bits")

    @pytest.mark.parametrize("tag", [
        "unwind_read_failed", "unwind_truncated", "unwind_unpack_failed",
        "unwind_version_invalid", "unwind_flags_reserved_bits",
        "unwind_codes_truncated",
    ])
    def test_each_unwind_priority_tag_resolves(self, tag):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(version=None, flags=None, errors=[tag]))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID, tag)

    def test_unwind_priority_first_match_wins(self):
        """
        unwind_read_failed outranks the later tags, including the version and
        flag anomalies the validator derives itself.
        """
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(version=5, flags=0x10,
                                errors=["unwind_codes_truncated",
                                        "unwind_read_failed"]))])
        issues = _run(ex)
        invalid = _details_for(issues, ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID)
        assert len(invalid) == 1
        assert invalid[0]["sub_reason"] == "unwind_read_failed"

    def test_derived_version_error_not_duplicated(self):
        """
        The validator appends unwind_version_invalid only if absent, so a
        parser that already reported it produces one issue, not two.
        """
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(version=5, errors=["unwind_version_invalid"]))])
        assert len(_details_for(_run(ex),
                                ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID)) == 1

    def test_arm_entries_have_no_unwind_checks(self):
        """ARM records carry unwind=None, so the decode checks must no-op."""
        ex = _make_ex(machine=0xAA64, arch="arm64", entry_size=8, size=8,
                      functions=[_make_arm_entry(0, 0x1500)])
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID not in _codes(_run(ex))


# =================================================================
# Chained unwind
# =================================================================

class TestUnwindChain:

    def test_valid_chain_target_not_flagged(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True,
                                chained_rva=0x4200))])
        assert ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID not in _codes(_run(ex))

    def test_missing_chain_target_flagged(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True, chained_rva=0))])
        issues = _run(ex)
        assert len(issues) == 1
        assert _has(issues, ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_missing")

    def test_none_chain_target_flagged_as_missing(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True,
                                chained_rva=None))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_missing")

    def test_unaligned_chain_target_flagged(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True,
                                chained_rva=0x4201))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_unaligned")

    def test_out_of_bounds_chain_target_flagged(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True,
                                chained_rva=0x99000))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_out_of_bounds")

    def test_self_referential_chain_target_flagged(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=True,
                                chained_rva=0x4100))])   # == its own unwind rva
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_self_reference")

    def test_chain_detected_from_flag_without_is_chained(self):
        """
        The chain check triggers on UNW_FLAG_CHAININFO even when the parser
        did not set is_chained, so a partial parse still gets validated.
        """
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0x04, is_chained=False,
                                chained_rva=0))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_missing")

    def test_chain_detected_from_is_chained_without_flag(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0, is_chained=True, chained_rva=0))])
        assert _has(_run(ex), ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                    "chain_target_missing")

    def test_unchained_entry_skips_chain_check(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x1000, 0x1050, 0x4100,
            unwind=_make_unwind(flags=0, is_chained=False, chained_rva=None))])
        assert ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID not in _codes(_run(ex))


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedAnomalies:

    def test_directory_and_entry_anomalies_emit_independently(self):
        ex = _make_ex(rva=0x4001, size=25, functions=[
            _make_entry(0, 0x1900, 0x1950, 0x4100),
            _make_entry(1, 0x1800, 0x1850, 0x4110),
        ])
        codes = set(_codes(_run(ex)))
        assert ReasonCodes.EXCEPTION_DIRECTORY_UNALIGNED in codes
        assert ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE in codes
        assert ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED in codes

    def test_one_entry_can_raise_several_distinct_codes(self):
        """Range, bounds and unwind faults are independent facts."""
        ex = _make_ex(size=12, functions=[_make_entry(
            0, 0x99000, 0x99000, 0x4101,
            unwind=_make_unwind(version=5))])
        codes = set(_codes(_run(ex)))
        assert ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS in codes
        assert ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID in codes
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_UNALIGNED in codes
        assert ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID in codes


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_dependency_contract(self):
        assert getattr(validate_exception_table, "_depends_on") == (
            "internal", "metadata")

    def test_returns_list(self):
        assert isinstance(_run(_make_ex(functions=_control_functions())), list)

    def test_each_issue_has_issue_and_details(self):
        ex = _make_ex(rva=0x4001, functions=_control_functions())
        for issue in _run(ex):
            assert set(issue) == {"issue", "details"}
            assert isinstance(issue["issue"], str)
            assert isinstance(issue["details"], dict)

    def test_json_serializable(self):
        import json
        ex = _make_ex(rva=0x4001, size=25,
                      truncations=["exception_entry_truncated"],
                      functions=[_make_entry(0, 0x99000, 0x99000, 0x4101,
                                             unwind=_make_unwind(version=5))])
        json.dumps(_run(ex))   # must not raise

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"] would
        overwrite the parent reason code. Validators must use "sub_reason".

        Exercises the directory, truncation, entry, range, bounds, sortedness,
        unwind and chain paths together.
        """
        ex = _make_ex(rva=0x4001, size=25,
                      truncations=["exception_entry_truncated"],
                      functions=[
                          _make_entry(0, 0x1900, 0x1950, 0x4100,
                                      unwind=_make_unwind(version=5)),
                          _make_entry(1, 0x1800, 0x1800, 0x4101,
                                      unwind=_make_unwind(flags=0x04,
                                                          is_chained=True,
                                                          chained_rva=0)),
                          _make_entry(2, 0, 0, 0, unwind=None,
                                      errors=["begin_rva_zero"]),
                      ])
        issues = _run(ex)
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_top_level_decode_avoids_reserved_reason_key(self):
        """The short-circuit path is unreachable above; pin it separately."""
        issues = _run(_make_ex(errors=["boom"]))
        assert issues
        assert "reason" not in issues[0]["details"]

    def test_unsupported_machine_avoids_reserved_reason_key(self):
        """This path also returns early and is mutually exclusive."""
        issues = _run(_make_ex(machine=0x014C, arch="unsupported",
                               entry_size=0))
        assert issues
        assert "reason" not in issues[0]["details"]


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_produces_identical_issues(self):
        import json
        ex = _make_ex(rva=0x4001, size=25,
                      truncations=["exception_entry_truncated",
                                   "exception_table_ragged_tail"],
                      functions=[
                          _make_entry(0, 0x1900, 0x1950, 0x4100,
                                      unwind=_make_unwind(version=5)),
                          _make_entry(1, 0x1800, 0x1800, 0x4101,
                                      unwind=_make_unwind(flags=0x04,
                                                          is_chained=True,
                                                          chained_rva=0)),
                      ])
        results = [_run(ex) for _ in range(20)]
        first = json.dumps(results[0], sort_keys=True)
        for r in results[1:]:
            assert json.dumps(r, sort_keys=True) == first

    def test_priority_resolution_deterministic(self):
        ex = _make_ex(size=12, functions=[_make_entry(
            0, None, None, None, unwind=None,
            errors=["unwind_rva_zero", "begin_rva_zero"])])
        results = [_run(ex) for _ in range(20)]
        for r in results[1:]:
            assert r == results[0]
        assert results[0][0]["details"]["sub_reason"] == "begin_rva_zero"
