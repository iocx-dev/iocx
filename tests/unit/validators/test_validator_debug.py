# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.debug.validate_debug.

Strategy:
- Input is the debug_struct dict produced by parser pe_debug, carried under
  internal["debug_struct"].
- Build dicts directly to isolate validator logic from parser behaviour.
- Tests assert on emitted REASONCODES and the details payload.

Layer note: the validator is @depends_on("internal", "metadata", "analysis"),
so it takes THREE positional arguments. SizeOfImage is read from
metadata["optional_header"]["size_of_image"] and threaded explicitly into the
_directory_invariants helpers; section geometry comes from analysis["sections"].
Keeping those in separate fixtures is deliberate - see
test_no_sections_falls_back_to_size_of_image.

Details note: priority-resolved sub-reasons are carried in a "sub_reason" key.
The key "reason" is reserved by the heuristics emission layer, which merges
details over its own reason field - a details["reason"] would overwrite the
parent reason code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.debug import validate_debug


# =================================================================
# Input builders
# =================================================================

def _make_metadata(size_of_image: Optional[int] = 0x100000) -> Dict[str, Any]:
    """
    Public-metadata layer. SizeOfImage lives under optional_header; it is NOT
    part of the analysis layer.
    """
    return {"optional_header": {"size_of_image": size_of_image}}


def _make_analysis(
    sections: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Analysis layer. Carries section geometry only.

    Deliberately does NOT accept a size_of_image argument: the previous fixture
    injected one here, which made the SizeOfImage fallback path appear to work
    in tests while it was dead in production (analysis never carries that key).
    Use _make_metadata for SizeOfImage.
    """
    analysis: Dict[str, Any] = {}
    if sections is not None:
        analysis["sections"] = sections
    return analysis


def _whole_image_sections() -> List[Dict[str, Any]]:
    return [{"virtual_address": 0x1000, "virtual_size": 0xFF000}]


def _tiny_section() -> List[Dict[str, Any]]:
    return [{"virtual_address": 0x1000, "virtual_size": 0x8}]


def _make_entry(
    index: int = 0,
    dtype: int = 2,
    type_name: Optional[str] = "CODEVIEW",
    size_of_data: int = 0x20,
    address_of_raw_data: int = 0x2000,
    pointer_to_raw_data: int = 0x900,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "index": index, "type": dtype, "type_name": type_name,
        "size_of_data": size_of_data,
        "address_of_raw_data": address_of_raw_data,
        "pointer_to_raw_data": pointer_to_raw_data,
        "errors": errors or [],
    }


def _make_debug(
    rva: int = 0x1000,
    size: int = 0x1C,
    entries: Optional[List[Dict[str, Any]]] = None,
    truncations: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ents = entries or []
    return {"rva": rva, "size": size, "entries": ents,
            "entry_count": len(ents),
            "truncations": truncations or [], "errors": errors or []}


def _run(debug: Optional[Dict[str, Any]],
         analysis: Dict[str, Any],
         metadata: Optional[Dict[str, Any]] = None):
    if metadata is None:
        metadata = _make_metadata()
    return validate_debug({"debug_struct": debug}, metadata, analysis)


def _codes(issues) -> List:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# Absence
# =================================================================

class TestAbsence:
    def test_none_struct_no_issues(self):
        assert _run(None, _make_analysis()) == []

    def test_missing_key_no_issues(self):
        assert validate_debug({}, _make_metadata(), _make_analysis()) == []


# =================================================================
# Top-level decode short-circuit
# =================================================================

class TestTopLevelDecodeFailure:
    def test_errors_emit_invalid_header(self):
        debug = _make_debug(errors=["entry_unpack_failed"])
        issues = _run(debug, _make_analysis())
        assert _codes(issues) == [ReasonCodes.DEBUG_DIRECTORY_INVALID_HEADER]
        d = _details_for(issues, ReasonCodes.DEBUG_DIRECTORY_INVALID_HEADER)[0]
        assert d["sub_reason"] == "top_level_decode"
        assert d["errors"] == ["entry_unpack_failed"]

    def test_short_circuit_skips_entries_and_truncations(self):
        debug = _make_debug(
            errors=["x"],
            truncations=["debug_entry_truncated"],
            entries=[_make_entry(errors=["codeview_too_short"])])
        issues = _run(debug, _make_analysis())
        assert _codes(issues) == [ReasonCodes.DEBUG_DIRECTORY_INVALID_HEADER]


# =================================================================
# Truncations
# =================================================================

class TestTruncations:
    def test_one_issue_per_tag(self):
        debug = _make_debug(truncations=[
            "debug_directory_size_not_entry_aligned",
            "debug_entry_truncated"])
        issues = _run(debug, _make_analysis())
        assert _codes(issues) == [
            ReasonCodes.DEBUG_TABLE_TRUNCATED,
            ReasonCodes.DEBUG_TABLE_TRUNCATED]

    def test_region_detail_preserved(self):
        debug = _make_debug(truncations=["debug_entry_read_failed"])
        issues = _run(debug, _make_analysis())
        # "region" is a distinct key and was never subject to the reason
        # collision, so it is unchanged by the sub_reason migration.
        assert _details_for(issues, ReasonCodes.DEBUG_TABLE_TRUNCATED)[0] == {
            "region": "debug_entry_read_failed"}


# =================================================================
# Entry malformation (priority-resolved)
# =================================================================

class TestEntryMalformation:
    def test_single_reason_flagged(self):
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0, pointer_to_raw_data=0,
            errors=["codeview_signature_unknown"])])
        issues = _run(debug, _make_analysis())
        assert ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED in _codes(issues)
        d = _details_for(issues, ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED)[0]
        assert d["sub_reason"] == "codeview_signature_unknown"
        assert d["index"] == 0 and d["type_name"] == "CODEVIEW"

    def test_priority_first_match_wins(self):
        # entry_unpack_failed outranks codeview_signature_unknown
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0, pointer_to_raw_data=0,
            errors=["codeview_signature_unknown", "entry_unpack_failed"])])
        issues = _run(debug, _make_analysis())
        malformed = _details_for(issues, ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED)
        assert len(malformed) == 1
        assert malformed[0]["sub_reason"] == "entry_unpack_failed"

    def test_unknown_error_not_flagged(self):
        # an error tag not in the priority list -> no malformation issue
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0, pointer_to_raw_data=0,
            errors=["some_unlisted_tag"])])
        issues = _run(debug, _make_analysis())
        assert ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED not in _codes(issues)

    def test_clean_entry_no_issue(self):
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x1004, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(sections=_whole_image_sections()))
        assert issues == []


# =================================================================
# Entry data-region RVA validation
# =================================================================

class TestEntryRvaValidation:
    def test_unmapped_region_flagged(self):
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x9000, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert _codes(issues) == [ReasonCodes.DEBUG_ENTRY_RVA_INVALID]
        d = _details_for(issues, ReasonCodes.DEBUG_ENTRY_RVA_INVALID)[0]
        assert d["index"] == 0
        assert d["address_of_raw_data"] == 0x9000
        assert d["size_of_data"] == 0x10

    def test_mapped_region_no_issue(self):
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x1004, size_of_data=0x4, errors=[])])
        issues = _run(debug, _make_analysis(sections=_whole_image_sections()))
        assert issues == []

    def test_zero_addr_not_checked(self):
        # AddressOfRawData == 0 (file-pointer-only entry) -> not flagged
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0, pointer_to_raw_data=0x900, errors=[])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert ReasonCodes.DEBUG_ENTRY_RVA_INVALID not in _codes(issues)

    def test_missing_size_defaults_zero(self):
        entry = _make_entry(address_of_raw_data=0x9000, errors=[])
        del entry["size_of_data"]  # size_of_data absent -> treated as 0
        debug = _make_debug(entries=[entry])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert _codes(issues) == [ReasonCodes.DEBUG_ENTRY_RVA_INVALID]
        assert _details_for(issues, ReasonCodes.DEBUG_ENTRY_RVA_INVALID)[0]["size_of_data"] == 0

    def test_no_sections_falls_back_to_size_of_image(self):
        """
        With no section geometry, the check falls back to a SizeOfImage bound.

        SizeOfImage must come from the METADATA layer. The previous version of
        this test put it in `analysis`, which the helpers used to read - so the
        fallback passed here while being dead in production, where `analysis`
        never carries that key.
        """
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x200000, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(),
                      metadata=_make_metadata(size_of_image=0x100000))
        assert _codes(issues) == [ReasonCodes.DEBUG_ENTRY_RVA_INVALID]

    def test_no_sections_in_bounds_not_flagged(self):
        """Counterpart: the fallback must not false-positive on a valid RVA."""
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x2000, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(),
                      metadata=_make_metadata(size_of_image=0x100000))
        assert ReasonCodes.DEBUG_ENTRY_RVA_INVALID not in _codes(issues)

    def test_no_sections_and_no_size_of_image_skips_check(self):
        """
        With neither section geometry nor SizeOfImage the check is unknowable
        and must be skipped rather than guessed. Pins the absent-optional-header
        case explicitly so it is asserted on purpose.
        """
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x200000, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(), metadata={})
        assert ReasonCodes.DEBUG_ENTRY_RVA_INVALID not in _codes(issues)

    def test_sections_take_precedence_over_size_of_image(self):
        """
        When section geometry is present it is authoritative: an RVA inside
        SizeOfImage but outside every section is still flagged.
        """
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x9000, size_of_data=0x10, errors=[])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()),
                      metadata=_make_metadata(size_of_image=0x100000))
        assert _codes(issues) == [ReasonCodes.DEBUG_ENTRY_RVA_INVALID]


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedAnomalies:
    def test_truncation_plus_entry_malformed(self):
        debug = _make_debug(
            truncations=["debug_entry_truncated"],
            entries=[_make_entry(address_of_raw_data=0, pointer_to_raw_data=0,
                                 errors=["codeview_rsds_truncated"])])
        issues = _run(debug, _make_analysis())
        assert _codes(issues) == [
            ReasonCodes.DEBUG_TABLE_TRUNCATED,
            ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED]

    def test_malformed_and_rva_invalid_same_entry(self):
        # a CodeView entry that is both malformed AND points its data region
        # at an unmapped RVA -> two issues for the one entry
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x9000, size_of_data=0x10,
            errors=["pdb_path_non_ascii"])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED in _codes(issues)
        assert ReasonCodes.DEBUG_ENTRY_RVA_INVALID in _codes(issues)


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:
    def test_dependency_contract(self):
        assert getattr(validate_debug, "_depends_on") == (
            "internal", "metadata", "analysis")

    def test_issue_shape(self):
        debug = _make_debug(entries=[_make_entry(
            address_of_raw_data=0x9000, errors=["codeview_too_short"])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert issues
        for i in issues:
            assert set(i) == {"issue", "details"}
            assert isinstance(i["issue"], str)
            assert isinstance(i["details"], dict)

    def test_json_serializable(self):
        import json
        debug = _make_debug(
            truncations=["debug_entry_truncated"],
            entries=[_make_entry(errors=["codeview_too_short"],
                                 address_of_raw_data=0, pointer_to_raw_data=0)])
        issues = _run(debug, _make_analysis())
        json.dumps([i for i in issues])

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"] would
        overwrite the parent reason code. Validators must use "sub_reason".

        Exercises every non-short-circuit emission path at once.
        """
        debug = _make_debug(
            truncations=["debug_entry_truncated"],
            entries=[_make_entry(address_of_raw_data=0x9000, size_of_data=0x10,
                                 errors=["codeview_signature_unknown"])])
        issues = _run(debug, _make_analysis(sections=_tiny_section()))
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_top_level_decode_avoids_reserved_reason_key(self):
        """The short-circuit path is unreachable above; pin it separately."""
        debug = _make_debug(errors=["entry_unpack_failed"])
        issues = _run(debug, _make_analysis())
        assert issues
        assert "reason" not in issues[0]["details"]


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def test_repeated_calls_identical(self):
        import json
        debug = _make_debug(
            truncations=["debug_entry_truncated"],
            entries=[_make_entry(address_of_raw_data=0x9000, size_of_data=0x10,
                                 errors=["codeview_signature_unknown"])])
        analysis = _make_analysis(sections=_tiny_section())
        a = [i for i in _run(debug, analysis)]
        b = [i for i in _run(debug, analysis)]
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
