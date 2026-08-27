# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.exports.validate_exports.

Strategy:
- Input is the export_struct dict produced by parser_exports.
- Build dicts directly; isolate validator logic from parser behaviour.
- Each test asserts on the set of REASONCODES emitted and the details
  payload.

Layer note: the validator is @depends_on("internal", "metadata"), so the second
positional argument is the PUBLIC METADATA layer, not the analysis layer.
SizeOfImage is read from metadata["optional_header"]["size_of_image"].

Details note: priority-resolved sub-reasons are carried in a "sub_reason" key.
The key "reason" is reserved by the heuristics emission layer, which merges
details over its own reason field - a details["reason"] would overwrite the
parent reason code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.exports import validate_exports


# =================================================================
# Input builders
# =================================================================

_NOT_PROVIDED = object()


def _make_metadata(size_of_image: Optional[int] = 0x100000) -> Dict[str, Any]:
    """
    Public-metadata layer. SizeOfImage lives under optional_header; passing
    None models an optional header present but missing the field.
    """
    return {"optional_header": {"size_of_image": size_of_image}}


def _make_header(
    base: int = 1,
    num_functions: int = 0,
    num_names: int = 0,
    addr_functions: int = 0x1100,
    addr_names: int = 0x1200,
    addr_name_ordinals: int = 0x1300,
    **overrides,
) -> Dict[str, int]:
    h = {
        "Characteristics": 0,
        "TimeDateStamp": 0,
        "MajorVersion": 0,
        "MinorVersion": 0,
        "Name": 0x1000,
        "Base": base,
        "NumberOfFunctions": num_functions,
        "NumberOfNames": num_names,
        "AddressOfFunctions": addr_functions if num_functions else 0,
        "AddressOfNames": addr_names if num_names else 0,
        "AddressOfNameOrdinals": addr_name_ordinals if num_names else 0,
    }
    h.update(overrides)
    return h


def _make_function(
    index: int = 0,
    ordinal: int = 1,
    address_rva: Optional[int] = 0x2000,
    is_forwarder: bool = False,
    forwarder: Optional[str] = None,
    forwarder_valid: bool = False,
    name: Optional[str] = None,
    name_rva: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "index": index,
        "ordinal": ordinal,
        "address_rva": address_rva,
        "is_forwarder": is_forwarder,
        "forwarder": forwarder,
        "forwarder_valid": forwarder_valid,
        "name": name,
        "name_rva": name_rva,
    }


def _make_name_pointer(
    index: int = 0,
    name_rva: Optional[int] = 0x1400,
    ordinal_index: Optional[int] = 0,
    name: Optional[str] = "Foo",
    name_valid: bool = True,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "index": index,
        "name_rva": name_rva,
        "ordinal_index": ordinal_index,
        "name": name,
        "name_valid": name_valid,
        "errors": errors or [],
    }


def _make_exp(
    rva: int = 0x1000,
    size: int = 200,
    header: Any = _NOT_PROVIDED,
    functions: Optional[List[Dict[str, Any]]] = None,
    name_pointers: Optional[List[Dict[str, Any]]] = None,
    truncations: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "rva": rva,
        "size": size,
        "header": _make_header() if header is _NOT_PROVIDED else header,
        "functions": functions or [],
        "name_pointers": name_pointers or [],
        "truncations": truncations or [],
        "errors": errors or [],
    }


def _codes(issues) -> List[Any]:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# Absence
# =================================================================

class TestAbsence:

    def test_no_export_struct_returns_no_issues(self):
        assert validate_exports({}, _make_metadata()) == []

    def test_explicit_none_returns_no_issues(self):
        assert validate_exports({"export_struct": None}, _make_metadata()) == []


# =================================================================
# Top-level decode short-circuit
# =================================================================

class TestTopLevelDecodeFailure:

    def test_errors_present_emits_invalid_returns_early(self):
        exp = _make_exp(errors=["header_read_failed"])
        # Add other issues that should NOT be emitted due to early return
        exp["truncations"] = ["eat_truncated"]
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        codes = _codes(issues)
        assert ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER in codes
        assert ReasonCodes.EXPORT_TABLE_TRUNCATED not in codes
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        assert details[0]["sub_reason"] == "top_level_decode"
        assert details[0]["errors"] == ["header_read_failed"]


# =================================================================
# Placement
# =================================================================

class TestPlacement:

    def test_in_bounds_no_issue(self):
        exp = _make_exp(rva=0x1000, size=200)
        metadata = _make_metadata(size_of_image=0x100000)
        issues = validate_exports({"export_struct": exp}, metadata)
        assert ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_extends_past_image_flagged(self):
        exp = _make_exp(rva=0xFFF00, size=0x200)
        metadata = _make_metadata(size_of_image=0x100000)
        issues = validate_exports({"export_struct": exp}, metadata)
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS)
        assert len(details) == 1
        assert details[0]["rva"] == 0xFFF00

    def test_silent_when_size_of_image_missing(self):
        exp = _make_exp(rva=0xFFF00, size=0x200)
        metadata = _make_metadata(size_of_image=None)
        issues = validate_exports({"export_struct": exp}, metadata)
        assert ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_silent_when_optional_header_absent(self):
        """
        The metadata layer may omit optional_header entirely. The placement
        check must skip rather than raise.

        Regression guard: while the fixture supplied size_of_image at the top
        level of the wrong layer, `optional_header` was always absent, so the
        OUT_OF_BOUNDS check could never fire and the sibling "silent" tests
        passed vacuously. This pins the absent-header case on purpose.
        """
        exp = _make_exp(rva=0xFFF00, size=0x200)
        issues = validate_exports({"export_struct": exp}, {})
        assert ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_silent_when_rva_none(self):
        exp = _make_exp(rva=None, size=0)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)


# =================================================================
# Truncations
# =================================================================

class TestTruncations:

    def test_no_truncations_no_issues(self):
        exp = _make_exp(truncations=[])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_TABLE_TRUNCATED not in _codes(issues)

    def test_single_truncation_emits_one_issue(self):
        exp = _make_exp(truncations=["eat_truncated"])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_TABLE_TRUNCATED)
        assert len(details) == 1
        # "table" is a distinct key and was never subject to the reason
        # collision, so it is unchanged by the sub_reason migration.
        assert details[0]["table"] == "eat_truncated"

    def test_multiple_truncations_emit_separate_issues(self):
        exp = _make_exp(truncations=["eat_truncated", "enpt_truncated", "eot_truncated"])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_TABLE_TRUNCATED)
        assert len(details) == 3
        tables = [d["table"] for d in details]
        assert set(tables) == {"eat_truncated", "enpt_truncated", "eot_truncated"}


# =================================================================
# Header consistency
# =================================================================

class TestHeaderConsistency:

    def test_clean_header_no_issues(self):
        header = _make_header(num_functions=2, num_names=2)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER not in _codes(issues)

    def test_eat_rva_zero_with_nonzero_count_flagged(self):
        header = _make_header(num_functions=5, addr_functions=0)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        reasons = [d["sub_reason"] for d in details]
        assert "eat_rva_zero_with_nonzero_count" in reasons

    def test_enpt_rva_zero_with_nonzero_count_flagged(self):
        header = _make_header(num_functions=5, num_names=3, addr_names=0)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        reasons = [d["sub_reason"] for d in details]
        assert "enpt_rva_zero_with_nonzero_count" in reasons

    def test_eot_rva_zero_with_nonzero_count_flagged(self):
        header = _make_header(num_functions=5, num_names=3, addr_name_ordinals=0)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        reasons = [d["sub_reason"] for d in details]
        assert "eot_rva_zero_with_nonzero_count" in reasons

    def test_num_names_exceeds_num_functions_flagged(self):
        header = _make_header(num_functions=2, num_names=5)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        reasons = [d["sub_reason"] for d in details]
        assert "num_names_exceeds_num_functions" in reasons

    def test_multiple_consistency_failures_emit_multiple_issues(self):
        header = _make_header(
            num_functions=5,
            num_names=10,  # > num_functions
            addr_functions=0,  # zero with count
        )
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
        assert len(details) >= 2

    def test_header_none_skips_consistency_check(self):
        exp = _make_exp(header=None, truncations=["export_directory_header"])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        # Should emit truncation but not consistency issues
        assert ReasonCodes.EXPORT_TABLE_TRUNCATED in _codes(issues)
        consistency = [
            d for d in _details_for(issues, ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER)
            if d.get("sub_reason") in {"eat_rva_zero_with_nonzero_count",
                                       "enpt_rva_zero_with_nonzero_count",
                                       "eot_rva_zero_with_nonzero_count",
                                       "num_names_exceeds_num_functions"}
        ]
        assert consistency == []


# =================================================================
# Name pointer validation
# =================================================================

class TestNamePointers:

    def test_clean_name_pointer_no_issues(self):
        np = _make_name_pointer()
        exp = _make_exp(
            header=_make_header(num_functions=1, num_names=1),
            name_pointers=[np],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_NAME_RVA_INVALID not in _codes(issues)
        assert ReasonCodes.EXPORT_NAME_NOT_ASCII not in _codes(issues)
        assert ReasonCodes.EXPORT_NAME_ORDINAL_INDEX_INVALID not in _codes(issues)

    def test_name_rva_zero_flagged(self):
        np = _make_name_pointer(errors=["name_rva_zero"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_RVA_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "name_rva_zero"

    def test_name_rva_priority_resolution(self):
        """name_rva_missing wins over read_failed when both are present."""
        np = _make_name_pointer(errors=["read_failed", "name_rva_missing"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_RVA_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "name_rva_missing"

    def test_unterminated_flagged_with_correct_reason(self):
        np = _make_name_pointer(errors=["unterminated"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_RVA_INVALID)
        assert details[0]["sub_reason"] == "unterminated"

    def test_non_ascii_flagged_with_correct_reason(self):
        np = _make_name_pointer(name="caf\ufffd", errors=["non_ascii"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_NOT_ASCII)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "non_ascii"

    def test_name_not_printable_ascii_flagged(self):
        np = _make_name_pointer(
            name="Foo\x01Bar",
            name_valid=False,
            errors=["name_not_printable_ascii"],
        )
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_NOT_ASCII)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "name_not_printable_ascii"

    def test_name_encoding_priority_resolution(self):
        """non_ascii wins over name_not_printable_ascii."""
        np = _make_name_pointer(
            errors=["name_not_printable_ascii", "non_ascii"],
        )
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_NOT_ASCII)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "non_ascii"

    def test_ordinal_index_missing_flagged(self):
        np = _make_name_pointer(errors=["ordinal_index_missing"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_ORDINAL_INDEX_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "missing"

    def test_ordinal_index_out_of_range_flagged(self):
        np = _make_name_pointer(
            ordinal_index=99,
            errors=["ordinal_index_out_of_range"],
        )
        exp = _make_exp(
            header=_make_header(num_functions=5, num_names=1),
            name_pointers=[np],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_ORDINAL_INDEX_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "out_of_range"
        assert details[0]["ordinal_index"] == 99
        assert details[0]["num_functions"] == 5

    def test_no_double_emission_per_entry(self):
        """An entry with multiple RVA-class errors emits only one issue."""
        np = _make_name_pointer(
            errors=["name_rva_zero", "name_rva_missing", "read_failed"],
        )
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        rva_issues = [
            i for i in issues
            if i["issue"] == ReasonCodes.EXPORT_NAME_RVA_INVALID
        ]
        assert len(rva_issues) == 1


# =================================================================
# Name pointer ordering
# =================================================================

class TestNamePointerOrdering:

    def test_sorted_names_no_issue(self):
        nps = [
            _make_name_pointer(index=0, name="Alpha"),
            _make_name_pointer(index=1, name="Beta"),
            _make_name_pointer(index=2, name="Gamma"),
        ]
        exp = _make_exp(
            header=_make_header(num_functions=3, num_names=3),
            name_pointers=nps,
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_NAME_POINTER_TABLE_UNSORTED not in _codes(issues)

    def test_unsorted_names_flagged(self):
        nps = [
            _make_name_pointer(index=0, name="Zeta"),
            _make_name_pointer(index=1, name="Alpha"),
        ]
        exp = _make_exp(
            header=_make_header(num_functions=2, num_names=2),
            name_pointers=nps,
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_NAME_POINTER_TABLE_UNSORTED)
        assert len(details) == 1
        # This code carries no sub_reason: its details were never subject to
        # the reason collision, so the ENPT ordering payload is unchanged.
        assert details[0]["name_count"] == 2
        assert details[0]["first_violation_index"] == 1
        assert "sub_reason" not in details[0]

    def test_unreadable_name_skips_ordering_check(self):
        nps = [
            _make_name_pointer(index=0, name=None, name_valid=False),
            _make_name_pointer(index=1, name="Zeta"),
        ]
        exp = _make_exp(name_pointers=nps)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_NAME_POINTER_TABLE_UNSORTED not in _codes(issues)

    def test_empty_name_pointers_no_issue(self):
        exp = _make_exp(name_pointers=[])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_NAME_POINTER_TABLE_UNSORTED not in _codes(issues)


# =================================================================
# Function entries
# =================================================================

class TestFunctions:

    def test_clean_function_no_issues(self):
        fn = _make_function(address_rva=0x2000)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)

    def test_max_ordinal_exceeds_u16_flagged(self):
        header = _make_header(base=0xFFF0, num_functions=32)
        exp = _make_exp(header=header, functions=[])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_ORDINAL_OUT_OF_RANGE)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "max_exceeds_u16"
        assert details[0]["base"] == 0xFFF0
        assert details[0]["max_ordinal"] == 0xFFF0 + 31

    def test_max_ordinal_in_range_no_issue(self):
        header = _make_header(base=1, num_functions=100)
        exp = _make_exp(header=header)
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_ORDINAL_OUT_OF_RANGE not in _codes(issues)

    def test_function_rva_within_image_no_issue(self):
        fn = _make_function(address_rva=0x5000)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports(
            {"export_struct": exp},
            _make_metadata(size_of_image=0x100000),
        )
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)

    def test_function_rva_beyond_image_flagged(self):
        fn = _make_function(address_rva=0x200000)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports(
            {"export_struct": exp},
            _make_metadata(size_of_image=0x100000),
        )
        details = _details_for(issues, ReasonCodes.EXPORT_FUNCTION_RVA_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "exceeds_image"
        assert details[0]["address_rva"] == 0x200000

    def test_zero_rva_function_skipped(self):
        """An EAT entry of 0 is 'unused slot' — not flagged."""
        fn = _make_function(address_rva=0)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)

    def test_none_rva_function_skipped(self):
        fn = _make_function(address_rva=None)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)

    def test_function_rva_check_silent_when_size_of_image_missing(self):
        fn = _make_function(address_rva=0x200000)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports(
            {"export_struct": exp},
            _make_metadata(size_of_image=None),
        )
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)

    def test_function_rva_check_silent_when_optional_header_absent(self):
        """
        Companion to the test above: with no optional_header at all the check
        must skip rather than raise. Pins the case that previously made the
        "silent" test pass vacuously.
        """
        fn = _make_function(address_rva=0x200000)
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, {})
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)


# =================================================================
# Forwarders
# =================================================================

class TestForwarders:

    def test_valid_forwarder_no_issue(self):
        fn = _make_function(
            address_rva=0x1050,
            is_forwarder=True,
            forwarder="KERNEL32.LoadLibraryA",
            forwarder_valid=True,
        )
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_FORWARDER_MALFORMED not in _codes(issues)

    def test_unreadable_forwarder_flagged(self):
        fn = _make_function(
            address_rva=0x1050,
            is_forwarder=True,
            forwarder=None,
            forwarder_valid=False,
        )
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_FORWARDER_MALFORMED)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "unreadable"

    def test_malformed_forwarder_format_flagged(self):
        fn = _make_function(
            address_rva=0x1050,
            is_forwarder=True,
            forwarder="NoDotInThisString",
            forwarder_valid=False,
        )
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        details = _details_for(issues, ReasonCodes.EXPORT_FORWARDER_MALFORMED)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "format"
        assert details[0]["forwarder"] == "NoDotInThisString"

    def test_forwarder_skips_function_rva_check(self):
        """A forwarder's address RVA points into the export directory; it
        should not also trigger EXPORT_FUNCTION_RVA_INVALID."""
        fn = _make_function(
            address_rva=0x1050,
            is_forwarder=True,
            forwarder="KERNEL32.X",
            forwarder_valid=True,
        )
        exp = _make_exp(
            header=_make_header(num_functions=1),
            functions=[fn],
        )
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert ReasonCodes.EXPORT_FUNCTION_RVA_INVALID not in _codes(issues)


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedAnomalies:

    def test_multiple_pathology_classes_emit_independently(self):
        # Bad placement, truncated EAT, bad name pointer
        exp = _make_exp(
            rva=0xFFF00,
            size=0x200,
            truncations=["eat_truncated"],
            name_pointers=[
                _make_name_pointer(errors=["name_rva_zero"]),
            ],
        )
        metadata = _make_metadata(size_of_image=0x100000)
        issues = validate_exports({"export_struct": exp}, metadata)
        codes = set(_codes(issues))
        assert ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS in codes
        assert ReasonCodes.EXPORT_TABLE_TRUNCATED in codes
        assert ReasonCodes.EXPORT_NAME_RVA_INVALID in codes


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_dependency_contract(self):
        assert getattr(validate_exports, "_depends_on") == ("internal", "metadata")

    def test_returns_list(self):
        result = validate_exports({"export_struct": _make_exp()}, _make_metadata())
        assert isinstance(result, list)

    def test_clean_exports_return_empty_list(self):
        result = validate_exports({"export_struct": _make_exp()}, _make_metadata())
        assert result == []

    def test_each_issue_has_issue_and_details(self):
        np = _make_name_pointer(errors=["name_rva_zero"])
        exp = _make_exp(name_pointers=[np])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        for issue in issues:
            assert "issue" in issue
            assert "details" in issue
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"] would
        overwrite the parent reason code. Validators must use "sub_reason".

        Exercises every non-short-circuit emission path at once: placement,
        truncation, all four header-consistency branches, both name-pointer
        pathology classes, ordinal-index, ordinal range, forwarder and
        function-RVA.
        """
        exp = _make_exp(
            rva=0xFFF00, size=0x200,
            header=_make_header(base=0xFFF0, num_functions=32, num_names=40,
                                addr_functions=0, addr_names=0,
                                addr_name_ordinals=0),
            truncations=["eat_truncated"],
            name_pointers=[_make_name_pointer(
                errors=["name_rva_zero", "non_ascii", "ordinal_index_missing"],
                name=None, name_valid=False)],
            functions=[
                _make_function(index=0, address_rva=0x200000),
                _make_function(index=1, address_rva=0x1050, is_forwarder=True,
                               forwarder=None, forwarder_valid=False),
            ],
        )
        issues = validate_exports({"export_struct": exp},
                                  _make_metadata(size_of_image=0x100000))
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_top_level_decode_avoids_reserved_reason_key(self):
        """The short-circuit path is unreachable above; pin it separately."""
        exp = _make_exp(errors=["header_read_failed"])
        issues = validate_exports({"export_struct": exp}, _make_metadata())
        assert issues
        assert "reason" not in issues[0]["details"]


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_produces_identical_issues(self):
        np = _make_name_pointer(
            name=None,
            name_valid=False,
            errors=["read_failed", "name_rva_missing"],
        )
        fn = _make_function(
            is_forwarder=True,
            forwarder="BAD",
            forwarder_valid=False,
        )
        exp = _make_exp(
            truncations=["eat_truncated", "eot_truncated"],
            name_pointers=[np],
            functions=[fn],
        )
        internal = {"export_struct": exp}
        metadata = _make_metadata()

        results = [validate_exports(internal, metadata) for _ in range(20)]
        for r in results[1:]:
            assert r == results[0]

    def test_priority_resolution_deterministic(self):
        np = _make_name_pointer(
            errors=["read_failed", "name_rva_zero", "name_rva_missing", "unterminated"],
        )
        exp = _make_exp(name_pointers=[np])
        results = [
            validate_exports({"export_struct": exp}, _make_metadata())
            for _ in range(20)
        ]
        for r in results[1:]:
            assert r == results[0]
        # Confirm priority winner
        details = _details_for(results[0], ReasonCodes.EXPORT_NAME_RVA_INVALID)
        assert details[0]["sub_reason"] == "name_rva_missing"
