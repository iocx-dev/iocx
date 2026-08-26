# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.delay_imports.validate_delay_imports.

Strategy:
- Input is the delay_import_struct dict produced by parser_delay_imports.
- Build dicts directly to isolate validator logic from parser behaviour.
- Tests assert on emitted REASONCODES and the details payload.

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
from iocx.validators.delay_imports import validate_delay_imports


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


def _make_entry(
    index: int = 0,
    is_ordinal: bool = False,
    ordinal: Optional[int] = None,
    hint: Optional[int] = 0x10,
    name: Optional[str] = "Foo",
    name_rva: Optional[int] = 0x6000,
    name_valid: bool = True,
    iat_value: Optional[int] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "index": index,
        "is_ordinal": is_ordinal,
        "ordinal": ordinal,
        "hint": hint,
        "name": name,
        "name_rva": name_rva,
        "name_valid": name_valid,
        "iat_value": iat_value,
        "errors": errors or [],
    }


def _make_descriptor(
    index: int = 0,
    attributes: int = 0x01,
    attributes_v1: bool = True,
    dll_name_rva: int = 0x2000,
    dll_name: Optional[str] = "test.dll",
    dll_name_valid: bool = True,
    module_handle_rva: int = 0x3000,
    iat_rva: int = 0x4000,
    int_rva: int = 0x5000,
    bound_iat_rva: int = 0,
    unload_iat_rva: int = 0,
    timestamp: int = 0,
    is_bound: bool = False,
    imports: Optional[List[Dict[str, Any]]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "index": index,
        "attributes": attributes,
        "attributes_v1": attributes_v1,
        "dll_name_rva": dll_name_rva,
        "dll_name": dll_name,
        "dll_name_valid": dll_name_valid,
        "module_handle_rva": module_handle_rva,
        "iat_rva": iat_rva,
        "int_rva": int_rva,
        "bound_iat_rva": bound_iat_rva,
        "unload_iat_rva": unload_iat_rva,
        "timestamp": timestamp,
        "is_bound": is_bound,
        "imports": imports or [],
        "errors": errors or [],
    }


def _make_di(
    rva: int = 0x1000,
    size: int = 64,
    is_64bit: bool = True,
    descriptors: Optional[List[Dict[str, Any]]] = None,
    truncations: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "rva": rva,
        "size": size,
        "is_64bit": is_64bit,
        "descriptors": descriptors or [],
        "truncations": truncations or [],
        "errors": errors or [],
    }


def _codes(issues) -> List:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# Absence
# =================================================================

class TestAbsence:

    def test_no_delay_import_struct_returns_no_issues(self):
        assert validate_delay_imports({}, _make_metadata()) == []

    def test_explicit_none_returns_no_issues(self):
        assert validate_delay_imports(
            {"delay_import_struct": None}, _make_metadata(),
        ) == []


# =================================================================
# Top-level decode short-circuit
# =================================================================

class TestTopLevelDecodeFailure:

    def test_errors_present_emits_invalid_header_and_returns_early(self):
        di = _make_di(errors=["header_read_failed"])
        di["truncations"] = ["delay_import_descriptor_truncated"]
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        codes = _codes(issues)
        assert ReasonCodes.DELAY_IMPORT_DIRECTORY_INVALID_HEADER in codes
        # Should not emit truncation issues due to early return
        assert ReasonCodes.DELAY_IMPORT_TABLE_TRUNCATED not in codes
        details = _details_for(issues,
                               ReasonCodes.DELAY_IMPORT_DIRECTORY_INVALID_HEADER)
        assert details[0]["sub_reason"] == "top_level_decode"


# =================================================================
# Placement
# =================================================================

class TestPlacement:

    def test_in_bounds_no_issue(self):
        di = _make_di(rva=0x1000, size=64)
        issues = validate_delay_imports(
            {"delay_import_struct": di},
            _make_metadata(size_of_image=0x100000),
        )
        assert ReasonCodes.DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_extends_past_image_flagged(self):
        di = _make_di(rva=0xFFFF0, size=0x200)
        issues = validate_delay_imports(
            {"delay_import_struct": di},
            _make_metadata(size_of_image=0x100000),
        )
        details = _details_for(issues,
                               ReasonCodes.DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS)
        assert len(details) == 1
        assert details[0]["rva"] == 0xFFFF0

    def test_silent_when_size_of_image_missing(self):
        di = _make_di(rva=0xFFFF0, size=0x200)
        issues = validate_delay_imports(
            {"delay_import_struct": di},
            _make_metadata(size_of_image=None),
        )
        assert ReasonCodes.DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)

    def test_silent_when_optional_header_absent(self):
        """
        The metadata layer may omit optional_header entirely. The placement
        check must skip rather than raise.

        Regression guard: while `optional_header` was absent the OUT_OF_BOUNDS
        check could never fire, so the two tests above passed vacuously. This
        test pins the absent-header case explicitly so that behaviour is
        asserted on purpose rather than by accident.
        """
        di = _make_di(rva=0xFFFF0, size=0x200)
        issues = validate_delay_imports({"delay_import_struct": di}, {})
        assert ReasonCodes.DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS not in _codes(issues)


# =================================================================
# Truncations
# =================================================================

class TestTruncations:

    def test_no_truncations_no_issues(self):
        di = _make_di(truncations=[])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        assert ReasonCodes.DELAY_IMPORT_TABLE_TRUNCATED not in _codes(issues)

    def test_single_truncation_emits_one_issue(self):
        di = _make_di(truncations=["delay_import_descriptor_truncated"])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_TABLE_TRUNCATED)
        assert len(details) == 1
        # "table" is a distinct key and was never subject to the reason
        # collision, so it is unchanged by the sub_reason migration.
        assert details[0]["table"] == "delay_import_descriptor_truncated"

    def test_multiple_truncations_emit_separate_issues(self):
        di = _make_di(truncations=[
            "delay_import_descriptor_truncated",
            "int_truncated",
            "iat_truncated",
        ])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_TABLE_TRUNCATED)
        assert len(details) == 3


# =================================================================
# Descriptor validation
# =================================================================

class TestDescriptorValidation:

    def test_clean_descriptor_no_issues(self):
        d = _make_descriptor()
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        assert issues == []

    def test_v0_attributes_flagged(self):
        d = _make_descriptor(attributes=0, attributes_v1=False)
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues,
                               ReasonCodes.DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE)
        assert len(details) == 1
        assert details[0]["index"] == 0
        assert details[0]["attributes"] == 0

    def test_dll_name_rva_zero_flagged(self):
        d = _make_descriptor(errors=["dll_name_rva_zero"])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "dll_name_rva_zero"

    def test_dll_name_priority_resolution(self):
        """dll_name_rva_zero wins over read_failed when both are present."""
        d = _make_descriptor(errors=["read_failed", "dll_name_rva_zero"])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "dll_name_rva_zero"

    def test_dll_name_not_printable_flagged(self):
        d = _make_descriptor(
            dll_name="kernel\x0132.dll",
            dll_name_valid=False,
            errors=["dll_name_not_printable"],
        )
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID)
        assert details[0]["sub_reason"] == "dll_name_not_printable"
        assert details[0]["dll_name"] == "kernel\x0132.dll"

    def test_int_rva_zero_flagged(self):
        d = _make_descriptor(errors=["int_rva_zero"], int_rva=0)
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_DESCRIPTOR_INVALID)
        # Find the INT-specific one
        int_details = [d for d in details if d["table"] == "int"]
        assert len(int_details) == 1
        assert int_details[0]["sub_reason"] == "int_rva_zero"

    def test_iat_rva_zero_flagged(self):
        d = _make_descriptor(errors=["iat_rva_zero"], iat_rva=0)
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_DESCRIPTOR_INVALID)
        iat_details = [d for d in details if d["table"] == "iat"]
        assert len(iat_details) == 1
        assert iat_details[0]["sub_reason"] == "iat_rva_zero"

    def test_int_iat_mismatch_flagged(self):
        d = _make_descriptor(errors=["int_iat_length_mismatch"])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_INT_IAT_MISMATCH)
        assert len(details) == 1
        assert details[0]["dll_name"] == "test.dll"

    def test_no_double_emission_per_descriptor(self):
        """A descriptor with multiple DLL-name errors emits only one issue."""
        d = _make_descriptor(
            errors=["dll_name_rva_zero", "read_failed", "unterminated"],
        )
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        dll_issues = [
            i for i in issues
            if i["issue"] == ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID
        ]
        assert len(dll_issues) == 1

    def test_entry_with_unknown_error_tag_skipped(self):
        """
        Cover the defensive guard: an entry whose errors contain only tags
        not in _ENTRY_ERROR_PRIORITY (e.g., a future parser tag that the
        validator's priority list hasn't been updated to recognise) is
        silently skipped without emitting a reason code.
        """
        e = _make_entry(errors=["future_parser_tag_not_yet_recognised"])
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        # No DELAY_IMPORT_ENTRY_INVALID should fire — the unknown tag is
        # not in the priority list, so the validator skips emission rather
        # than reporting a spurious "unknown" reason.
        assert ReasonCodes.DELAY_IMPORT_ENTRY_INVALID not in _codes(issues)


# =================================================================
# Entry validation
# =================================================================

class TestEntryValidation:

    def test_clean_entry_no_issues(self):
        e = _make_entry()
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        assert ReasonCodes.DELAY_IMPORT_ENTRY_INVALID not in _codes(issues)

    def test_ordinal_zero_flagged(self):
        e = _make_entry(
            is_ordinal=True, ordinal=0,
            errors=["ordinal_zero"],
        )
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "ordinal_zero"
        assert details[0]["is_ordinal"] is True
        assert details[0]["ordinal"] == 0

    def test_int_entry_missing_flagged(self):
        e = _make_entry(errors=["int_entry_missing"])
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert details[0]["sub_reason"] == "int_entry_missing"

    def test_int_entry_zero_flagged(self):
        e = _make_entry(errors=["int_entry_zero"])
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert details[0]["sub_reason"] == "int_entry_zero"

    def test_name_unterminated_flagged(self):
        e = _make_entry(
            name=None, name_valid=False,
            errors=["name_unterminated"],
        )
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert details[0]["sub_reason"] == "name_unterminated"

    def test_name_not_printable_flagged(self):
        e = _make_entry(
            name="Foo\x01Bar", name_valid=False,
            errors=["name_not_printable"],
        )
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert details[0]["sub_reason"] == "name_not_printable"
        assert details[0]["name"] == "Foo\x01Bar"

    def test_entry_priority_resolution(self):
        """int_entry_missing wins over name_unterminated."""
        e = _make_entry(errors=["name_unterminated", "int_entry_missing"])
        d = _make_descriptor(imports=[e])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert details[0]["sub_reason"] == "int_entry_missing"

    def test_multiple_bad_entries_each_flagged(self):
        e1 = _make_entry(index=0, errors=["int_entry_missing"])
        e2 = _make_entry(index=1, errors=["name_unterminated"])
        e3 = _make_entry(index=2)  # clean
        d = _make_descriptor(imports=[e1, e2, e3])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        details = _details_for(issues, ReasonCodes.DELAY_IMPORT_ENTRY_INVALID)
        assert len(details) == 2


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedAnomalies:

    def test_v0_with_cascading_dll_errors_emits_both(self):
        d = _make_descriptor(
            attributes=0, attributes_v1=False,
            errors=["dll_name_not_printable"],
        )
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        codes = set(_codes(issues))
        assert ReasonCodes.DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE in codes
        assert ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID in codes

    def test_multiple_descriptors_each_independently_validated(self):
        d1 = _make_descriptor(index=0, errors=["dll_name_rva_zero"])
        d2 = _make_descriptor(index=1, attributes=0, attributes_v1=False)
        di = _make_di(descriptors=[d1, d2])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        codes = set(_codes(issues))
        assert ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID in codes
        assert ReasonCodes.DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE in codes


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_returns_list(self):
        result = validate_delay_imports(
            {"delay_import_struct": _make_di()}, _make_metadata(),
        )
        assert isinstance(result, list)

    def test_clean_returns_empty_list(self):
        result = validate_delay_imports(
            {"delay_import_struct": _make_di()}, _make_metadata(),
        )
        assert result == []

    def test_each_issue_has_issue_and_details(self):
        d = _make_descriptor(errors=["dll_name_rva_zero"])
        di = _make_di(descriptors=[d])
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(),
        )
        for issue in issues:
            assert "issue" in issue
            assert "details" in issue
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"]
        would overwrite the parent reason code. Validators must use
        "sub_reason".

        Exercises every emission path in this validator at once.
        """
        d = _make_descriptor(
            attributes=0, attributes_v1=False,
            errors=[
                "dll_name_rva_zero", "int_rva_zero", "iat_rva_zero",
                "int_iat_length_mismatch",
            ],
            imports=[_make_entry(errors=["ordinal_zero"])],
        )
        di = _make_di(
            rva=0xFFFF0, size=0x200,
            truncations=["delay_import_descriptor_truncated"],
            descriptors=[d],
        )
        issues = validate_delay_imports(
            {"delay_import_struct": di}, _make_metadata(size_of_image=0x100000),
        )
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_produces_identical_issues(self):
        d = _make_descriptor(
            attributes=0, attributes_v1=False,
            errors=["dll_name_not_printable", "int_iat_length_mismatch"],
            imports=[
                _make_entry(index=0, errors=["int_entry_missing"]),
                _make_entry(index=1, errors=["name_unterminated"]),
            ],
        )
        di = _make_di(
            truncations=["delay_import_descriptor_truncated"],
            descriptors=[d],
        )
        internal = {"delay_import_struct": di}
        metadata = _make_metadata()

        results = [
            validate_delay_imports(internal, metadata) for _ in range(20)
        ]
        for r in results[1:]:
            assert r == results[0]

    def test_priority_resolution_deterministic(self):
        d = _make_descriptor(
            errors=["read_failed", "dll_name_rva_zero", "unterminated"],
        )
        di = _make_di(descriptors=[d])
        results = [
            validate_delay_imports(
                {"delay_import_struct": di}, _make_metadata(),
            )
            for _ in range(20)
        ]
        for r in results[1:]:
            assert r == results[0]
        # Confirm priority winner
        details = _details_for(results[0],
                               ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID)
        assert details[0]["sub_reason"] == "dll_name_rva_zero"
