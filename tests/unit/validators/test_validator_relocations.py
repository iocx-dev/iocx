# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.relocations.validate_relocations.

Strategy:
- Input is the relocation_struct dict produced by parser pe_relocations,
  carried under metadata["relocation_struct"].
- Build dicts directly to isolate validator logic from parser behaviour.
- Tests assert on emitted REASONCODES and the details payload.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.relocations import (
    validate_relocations,
    _MAX_ENTRY_ISSUES_PER_BLOCK,
)


# =================================================================
# Input builders
# =================================================================

def _make_analysis(
    size_of_image: Optional[int] = 0x100000,
    sections: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    analysis: Dict[str, Any] = {"size_of_image": size_of_image}
    if sections is not None:
        analysis["sections"] = sections
    return analysis


def _whole_image_sections() -> List[Dict[str, Any]]:
    """One section spanning the fixtures' target RVAs -> targets map cleanly."""
    return [{"virtual_address": 0x1000, "virtual_size": 0xFF000}]


def _tiny_section() -> List[Dict[str, Any]]:
    """A section too small to contain any real target -> targets miss."""
    return [{"virtual_address": 0x1000, "virtual_size": 0x8}]


def _make_entry(
    reloc_type: int = 3,
    type_name: Optional[str] = "HIGHLOW",
    offset: int = 0x10,
    rva: int = 0x2010,
) -> Dict[str, Any]:
    return {"type": reloc_type, "type_name": type_name,
            "offset": offset, "rva": rva}


def _make_block(
    index: int = 0,
    block_rva: int = 0x1000,
    page_rva: int = 0x2000,
    size_of_block: int = 0x10,
    entries: Optional[List[Dict[str, Any]]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ents = entries or []
    return {"index": index, "block_rva": block_rva, "page_rva": page_rva,
            "size_of_block": size_of_block, "entry_count": len(ents),
            "entries": ents, "errors": errors or []}


def _make_reloc(
    rva: int = 0x1000,
    size: int = 0x40,
    blocks: Optional[List[Dict[str, Any]]] = None,
    truncations: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    blks = blocks or []
    return {"rva": rva, "size": size, "blocks": blks,
            "block_count": len(blks),
            "entry_count": sum(len(b["entries"]) for b in blks),
            "truncations": truncations or [], "errors": errors or []}


def _run(reloc: Optional[Dict[str, Any]], analysis: Dict[str, Any]):
    return validate_relocations({"relocation_struct": reloc}, analysis)


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
        assert validate_relocations({}, _make_analysis()) == []


# =================================================================
# Top-level decode short-circuit
# =================================================================

class TestTopLevelDecodeFailure:
    def test_errors_emit_invalid_header(self):
        reloc = _make_reloc(errors=["block_header_unpack_failed_at_0"])
        issues = _run(reloc, _make_analysis())
        assert _codes(issues) == [ReasonCodes.RELOCATION_DIRECTORY_INVALID_HEADER]
        details = _details_for(issues, ReasonCodes.RELOCATION_DIRECTORY_INVALID_HEADER)[0]
        assert details["reason"] == "top_level_decode"
        assert details["errors"] == ["block_header_unpack_failed_at_0"]

    def test_short_circuit_skips_blocks_and_truncations(self):
        reloc = _make_reloc(
            errors=["x"],
            truncations=["relocation_entries_truncated"],
            blocks=[_make_block(errors=["size_of_block_too_small"])],
        )
        issues = _run(reloc, _make_analysis())
        # only the header issue; block/truncation checks never run
        assert _codes(issues) == [ReasonCodes.RELOCATION_DIRECTORY_INVALID_HEADER]


# =================================================================
# Truncations
# =================================================================

class TestTruncations:
    def test_one_issue_per_tag(self):
        reloc = _make_reloc(truncations=[
            "relocation_entries_truncated",
            "relocation_block_header_truncated"])
        issues = _run(reloc, _make_analysis())
        assert _codes(issues) == [
            ReasonCodes.RELOCATION_TABLE_TRUNCATED,
            ReasonCodes.RELOCATION_TABLE_TRUNCATED]

    def test_region_detail_preserved_in_order(self):
        reloc = _make_reloc(truncations=["relocation_entries_truncated",
                                         "relocation_block_read_failed"])
        issues = _run(reloc, _make_analysis())
        regions = [d["region"] for d in
                   _details_for(issues, ReasonCodes.RELOCATION_TABLE_TRUNCATED)]
        assert regions == ["relocation_entries_truncated",
                           "relocation_block_read_failed"]


# =================================================================
# Block validation
# =================================================================

class TestBlockValidation:
    def test_size_too_small_flagged(self):
        reloc = _make_reloc(blocks=[
            _make_block(errors=["size_of_block_too_small"])])
        issues = _run(reloc, _make_analysis())
        assert ReasonCodes.RELOCATION_BLOCK_MALFORMED in _codes(issues)
        d = _details_for(issues, ReasonCodes.RELOCATION_BLOCK_MALFORMED)[0]
        assert d["reason"] == "size_of_block_too_small"
        assert d["index"] == 0

    def test_priority_first_match_wins(self):
        # both errors present -> the higher-priority one is reported, once
        reloc = _make_reloc(blocks=[_make_block(errors=[
            "size_of_block_not_word_aligned", "size_of_block_too_small"])])
        issues = _run(reloc, _make_analysis())
        malformed = _details_for(issues, ReasonCodes.RELOCATION_BLOCK_MALFORMED)
        assert len(malformed) == 1
        assert malformed[0]["reason"] == "size_of_block_too_small"

    def test_clean_block_no_issue(self):
        reloc = _make_reloc(blocks=[_make_block(
            entries=[_make_entry(rva=0x2010)])])
        issues = _run(reloc, _make_analysis(sections=_whole_image_sections()))
        assert issues == []


# =================================================================
# Entry validation
# =================================================================

class TestEntryValidation:
    def test_absolute_entries_never_flagged(self):
        reloc = _make_reloc(blocks=[_make_block(entries=[
            {"type": 0, "type_name": "ABSOLUTE", "offset": 0, "rva": 0x2000}])])
        # even with a tiny section, ABSOLUTE padding is ignored
        issues = _run(reloc, _make_analysis(sections=_tiny_section()))
        assert issues == []

    def test_unmapped_target_flagged(self):
        reloc = _make_reloc(blocks=[_make_block(entries=[
            _make_entry(rva=0x9000)])])
        issues = _run(reloc, _make_analysis(sections=_tiny_section()))
        assert _codes(issues) == [ReasonCodes.RELOCATION_ENTRY_RVA_INVALID]
        d = _details_for(issues, ReasonCodes.RELOCATION_ENTRY_RVA_INVALID)[0]
        assert d["block_index"] == 0
        assert d["rva"] == 0x9000
        assert d["invalid_entry_count"] == 1

    def test_mapped_target_no_issue(self):
        reloc = _make_reloc(blocks=[_make_block(entries=[
            _make_entry(rva=0x1004)])])
        issues = _run(reloc, _make_analysis(sections=_whole_image_sections()))
        assert issues == []

    def test_count_reported_and_capped(self):
        # 12 invalid entries -> capped at _MAX_ENTRY_ISSUES_PER_BLOCK issues,
        # but invalid_entry_count carries the true total.
        entries = [_make_entry(offset=i, rva=0x9000 + i) for i in range(12)]
        reloc = _make_reloc(blocks=[_make_block(entries=entries)])
        issues = _run(reloc, _make_analysis(sections=_tiny_section()))
        assert len(issues) == _MAX_ENTRY_ISSUES_PER_BLOCK
        assert all(d["invalid_entry_count"] == 12
                   for d in _details_for(issues,
                                         ReasonCodes.RELOCATION_ENTRY_RVA_INVALID))

    def test_no_sections_falls_back_to_size_of_image(self):
        # No sections -> region_within_image bound check against size_of_image
        reloc = _make_reloc(blocks=[_make_block(entries=[
            _make_entry(rva=0x200000)])])  # beyond size_of_image
        issues = _run(reloc, _make_analysis(size_of_image=0x100000))
        assert _codes(issues) == [ReasonCodes.RELOCATION_ENTRY_RVA_INVALID]


# =================================================================
# Placement (owned by rva_graph — NOT re-checked here)
# =================================================================

class TestPlacementNotChecked:
    def test_out_of_bounds_directory_emits_no_placement_issue(self):
        # A directory whose rva+size exceeds size_of_image must NOT produce a
        # placement finding from this validator (rva_graph owns that).
        reloc = _make_reloc(rva=0x90000, size=0x2000,
                            blocks=[_make_block(entries=[_make_entry(rva=0x1004)])])
        issues = _run(reloc, _make_analysis(
            size_of_image=0x10000, sections=_whole_image_sections()))
        assert issues == []


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedAnomalies:
    def test_truncation_plus_block_malformed(self):
        reloc = _make_reloc(
            truncations=["relocation_entries_truncated"],
            blocks=[_make_block(errors=["size_of_block_too_small"])])
        issues = _run(reloc, _make_analysis())
        assert _codes(issues) == [
            ReasonCodes.RELOCATION_TABLE_TRUNCATED,
            ReasonCodes.RELOCATION_BLOCK_MALFORMED]

    def test_malformed_block_plus_invalid_entries(self):
        block = _make_block(
            errors=["size_of_block_not_word_aligned"],
            entries=[_make_entry(rva=0x9000), _make_entry(rva=0x9004)])
        issues = _run(_make_reloc(blocks=[block]),
                      _make_analysis(sections=_tiny_section()))
        codes = _codes(issues)
        assert codes[0] == ReasonCodes.RELOCATION_BLOCK_MALFORMED
        assert codes.count(ReasonCodes.RELOCATION_ENTRY_RVA_INVALID) == 2


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:
    def test_dependency_contract(self):
        assert getattr(validate_relocations, "_depends_on") == ("internal", "analysis")

    def test_issue_shape(self):
        reloc = _make_reloc(blocks=[_make_block(entries=[
            _make_entry(rva=0x9000)])])
        issues = _run(reloc, _make_analysis(sections=_tiny_section()))
        assert issues
        for i in issues:
            assert set(i) == {"issue", "details"}
            assert isinstance(i["issue"], str)
            assert isinstance(i["details"], dict)

    def test_json_serializable(self):
        import json
        reloc = _make_reloc(
            truncations=["relocation_entries_truncated"],
            blocks=[_make_block(errors=["size_of_block_too_small"])])
        issues = _run(reloc, _make_analysis())
        json.dumps([i for i in issues])  # must not raise


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def test_repeated_calls_identical(self):
        import json
        block = _make_block(
            errors=["size_of_block_not_word_aligned"],
            entries=[_make_entry(rva=0x9000), _make_entry(rva=0x9004)])
        reloc = _make_reloc(
            truncations=["relocation_entries_truncated"], blocks=[block])
        analysis = _make_analysis(sections=_tiny_section())
        a = [i for i in _run(reloc, analysis)]
        b = [i for i in _run(reloc, analysis)]
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
