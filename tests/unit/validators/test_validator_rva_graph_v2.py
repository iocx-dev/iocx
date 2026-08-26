# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.rva_graph.validate_rva_graph.

Layer note: @depends_on("metadata", "analysis"), TWO positional arguments.
SizeOfImage and SizeOfHeaders come from metadata["optional_header"]; sections
and overlay_offset from analysis. `data_directories` is read from analysis
FIRST, falling back to metadata - a subtlety pinned below.

Fixture note: this validator's checks do NOT short-circuit each other. A
directory can be in-headers AND unmapped; an overlay hit can be preceded by a
raw-mismatch. Several fixtures here therefore assert the FULL issue list
rather than mere presence, because a presence-only assertion hides how many
codes a fixture really trips.

Sections in these fixtures carry an explicit `raw_size` wherever overlay or
raw-mapping logic is exercised. Omitting it makes `sec.get("raw_size", 0)`
zero, which collapses the section's raw range to a point and trips
DATA_DIRECTORY_RAW_MISMATCH before the intended check - an easy fixture trap.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from iocx.validators.rva_graph import (
    validate_rva_graph,
    _is_security_directory,
    _SECURITY_DIRECTORY_INDEX,
    _SECURITY_DIRECTORY_NAME,
)
from iocx.reason_codes import ReasonCodes


# =================================================================
# Helpers
# =================================================================

def _dir(name: str = "dir", rva: Any = 0x1000, size: Any = 0x100,
         **extra) -> Dict[str, Any]:
    d = {"name": name, "rva": rva, "size": size}
    d.update(extra)
    return d


def _section(name: str = ".text", va: Any = 0x1000, vs: Any = 0x1000,
             raw: Any = 0x400, raw_size: Any = 0x1000) -> Dict[str, Any]:
    """A section with a raw range wide enough not to trip RAW_MISMATCH."""
    sec = {"name": name, "virtual_address": va, "virtual_size": vs}
    if raw is not None:
        sec["raw_address"] = raw
    if raw_size is not None:
        sec["raw_size"] = raw_size
    return sec


def _meta(size_of_image: Any = 0x3000, size_of_headers: Any = None,
          **extra) -> Dict[str, Any]:
    opt: Dict[str, Any] = {"size_of_image": size_of_image}
    if size_of_headers is not None:
        opt["size_of_headers"] = size_of_headers
    md: Dict[str, Any] = {"optional_header": opt}
    md.update(extra)
    return md


def _run(metadata: Dict[str, Any], **analysis) -> List[Dict[str, Any]]:
    return validate_rva_graph(metadata, analysis)


def make_issue_list(result) -> List[str]:
    return [i["issue"] for i in result]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# Early return / input tolerance
# =================================================================

class TestEarlyReturn:

    def test_missing_size_of_image_returns_empty(self):
        assert _run({"optional_header": {}},
                    data_directories=[_dir(rva=-1, size=-1)]) == []

    def test_missing_optional_header_returns_empty(self):
        assert _run({}, data_directories=[_dir(rva=-1, size=-1)]) == []

    def test_none_optional_header_returns_empty(self):
        assert _run({"optional_header": None},
                    data_directories=[_dir(rva=-1, size=-1)]) == []

    @pytest.mark.parametrize("value", ["1000", None, 1000.5, []])
    def test_non_int_size_of_image_returns_empty(self, value):
        """A float SizeOfImage is rejected, not coerced."""
        assert _run(_meta(size_of_image=value),
                    data_directories=[_dir(rva=-1, size=-1)]) == []

    def test_no_directories_returns_empty(self):
        assert _run(_meta()) == []

    def test_none_sections_tolerated(self):
        assert _run(_meta(), sections=None,
                    data_directories=[_dir(rva=0, size=0)]) == []

    @pytest.mark.parametrize("rva,size", [
        ("bad", 0x100), (0x1000, "bad"), (None, 0x100), (0x1000, None),
        (0x1000, 1.5), (1.5, 0x100),
    ])
    def test_non_int_directory_fields_skipped(self, rva, size):
        assert _run(_meta(), data_directories=[_dir(rva=rva, size=size)]) == []

    def test_malformed_section_fields_skipped(self):
        """A section with non-int VA/VS never enters section_ranges."""
        issues = _run(_meta(),
                      sections=[_section(va="bad"), _section(".ok", 0x1000)],
                      data_directories=[_dir(rva=0x1000, size=0x10)])
        assert issues == []


# =================================================================
# data_directories source resolution
# =================================================================

class TestDirectorySource:
    """`analysis.get(...) or metadata.get(...) or []` - order matters."""

    def test_analysis_is_preferred(self):
        md = _meta(data_directories=[_dir("FROM_METADATA", 0x2000, 0x10)])
        issues = _run(md, data_directories=[_dir("FROM_ANALYSIS", 0x2000, 0x10)])
        assert _details_for(
            issues, ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION
        )[0]["directory"] == "FROM_ANALYSIS"

    def test_metadata_used_when_analysis_absent(self):
        md = _meta(data_directories=[_dir("FROM_METADATA", 0x2000, 0x10)])
        issues = _run(md)
        assert _details_for(
            issues, ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION
        )[0]["directory"] == "FROM_METADATA"

    def test_empty_analysis_list_falls_through_to_metadata(self):
        """
        An empty list is falsy, so `or` continues to metadata. Subtle: an
        analysis layer that legitimately reports "no directories" does not
        suppress the metadata copy.
        """
        md = _meta(data_directories=[_dir("FROM_METADATA", 0x2000, 0x10)])
        issues = _run(md, data_directories=[])
        assert _details_for(
            issues, ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION
        )[0]["directory"] == "FROM_METADATA"

    def test_neither_source_yields_empty(self):
        assert _run(_meta()) == []


# =================================================================
# Security directory exclusion
# =================================================================

class TestSecurityDirectoryExclusion:
    """
    IMAGE_DIRECTORY_ENTRY_SECURITY carries a FILE OFFSET, not an RVA, so every
    RVA-based check here would be a category error. It must be excluded from
    BOTH the per-directory loop and the overlap loop.
    """

    def test_helper_matches_by_index(self):
        assert _is_security_directory({"index": _SECURITY_DIRECTORY_INDEX})

    def test_helper_matches_by_name(self):
        assert _is_security_directory({"name": _SECURITY_DIRECTORY_NAME})

    def test_helper_rejects_other_directories(self):
        assert not _is_security_directory({"index": 3, "name": "OTHER"})

    def test_helper_tolerates_missing_keys(self):
        assert not _is_security_directory({})

    @pytest.mark.parametrize("key,value", [
        ("index", _SECURITY_DIRECTORY_INDEX),
        ("name", _SECURITY_DIRECTORY_NAME),
    ])
    def test_excluded_from_per_directory_checks(self, key, value):
        """
        Negative rva/size would normally trip INVALID_RANGE; for security it
        must be silent.
        """
        d = {key: value, "rva": -1, "size": -1}
        assert _run(_meta(), data_directories=[d]) == []

    def test_non_security_directory_with_same_values_is_flagged(self):
        """Control: proves the exclusion, not the values, causes the silence."""
        issues = _run(_meta(), data_directories=[_dir("OTHER", -1, -1)])
        assert make_issue_list(issues) == [ReasonCodes.DATA_DIRECTORY_INVALID_RANGE]

    def test_excluded_from_overlap_as_first_operand(self):
        dirs = [{"index": _SECURITY_DIRECTORY_INDEX, "rva": 0x1000, "size": 0x100},
                _dir("B", 0x1050, 0x100)]
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(
            _run(_meta(), sections=[_section()], data_directories=dirs))

    def test_excluded_from_overlap_as_second_operand(self):
        dirs = [_dir("A", 0x1000, 0x100),
                {"index": _SECURITY_DIRECTORY_INDEX, "rva": 0x1050,
                 "size": 0x100}]
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(
            _run(_meta(), sections=[_section()], data_directories=dirs))

    def test_two_non_security_directories_do_overlap(self):
        """Control for the two exclusion tests above."""
        dirs = [_dir("A", 0x1000, 0x100), _dir("B", 0x1050, 0x100)]
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP in make_issue_list(
            _run(_meta(), sections=[_section()], data_directories=dirs))


# =================================================================
# Per-directory value checks
# =================================================================

class TestDirectoryValueChecks:

    @pytest.mark.parametrize("rva,size", [(-1, 0x10), (0x1000, -1), (-1, -1)])
    def test_negative_values_flagged(self, rva, size):
        issues = _run(_meta(), data_directories=[_dir(rva=rva, size=size)])
        assert make_issue_list(issues) == [ReasonCodes.DATA_DIRECTORY_INVALID_RANGE]

    def test_negative_values_short_circuit_later_checks(self):
        """`continue` means no mapping or overlay codes follow."""
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section()],
                      data_directories=[_dir(rva=-1, size=-1)])
        assert len(issues) == 1

    def test_empty_directory_is_silent(self):
        assert _run(_meta(), data_directories=[_dir(rva=0, size=0)]) == []

    def test_empty_directory_flagged_when_required(self, monkeypatch):
        from iocx.validators import rva_graph
        monkeypatch.setattr(rva_graph, "REQUIRED_NONZERO_DIRS", {"dir"})
        issues = rva_graph.validate_rva_graph(
            _meta(), {"data_directories": [_dir(rva=0, size=0)]})
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED]

    def test_required_nonzero_dirs_is_empty_by_default(self):
        """
        The default set is empty, so the ZERO_SIZE_UNEXPECTED branch is
        unreachable in production. Pinned so a future addition is deliberate.
        """
        from iocx.validators import rva_graph
        assert rva_graph.REQUIRED_NONZERO_DIRS == set()

    def test_zero_rva_nonzero_size_flagged(self):
        issues = _run(_meta(), data_directories=[_dir(rva=0, size=0x50)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE]

    def test_zero_size_nonzero_rva_flagged(self):
        """"Absent" and "present" simultaneously - a distinct malformation."""
        issues = _run(_meta(), data_directories=[_dir(rva=0x1000, size=0)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA]

    def test_zero_rva_and_zero_size_variants_are_distinct(self):
        """The three zero-combinations map to three different outcomes."""
        both_zero = _run(_meta(), data_directories=[_dir(rva=0, size=0)])
        rva_zero = _run(_meta(), data_directories=[_dir(rva=0, size=0x50)])
        size_zero = _run(_meta(), data_directories=[_dir(rva=0x1000, size=0)])
        assert both_zero == []
        assert make_issue_list(rva_zero) == [
            ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE]
        assert make_issue_list(size_zero) == [
            ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA]

    def test_details_payloads(self):
        issues = _run(_meta(), data_directories=[_dir("D", -5, 0x10)])
        assert _details_for(issues, ReasonCodes.DATA_DIRECTORY_INVALID_RANGE)[0] == {
            "directory": "D", "rva": -5, "size": 0x10}

    def test_directory_named_by_index_when_name_absent(self):
        """`d.get("name") or d.get("index")` - index is the fallback label."""
        issues = _run(_meta(),
                      data_directories=[{"index": 7, "rva": -1, "size": -1}])
        assert _details_for(
            issues, ReasonCodes.DATA_DIRECTORY_INVALID_RANGE)[0]["directory"] == 7


# =================================================================
# Headers and range
# =================================================================

class TestHeadersAndRange:

    def test_directory_in_headers_flagged(self):
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section(va=0x100, vs=0x1000)],
                      data_directories=[_dir(rva=0x200, size=0x10)])
        assert ReasonCodes.DATA_DIRECTORY_IN_HEADERS in make_issue_list(issues)

    def test_rva_exactly_at_size_of_headers_not_flagged(self):
        """The comparison is `<`, so the boundary itself is legal."""
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section(va=0x400, vs=0x1000)],
                      data_directories=[_dir(rva=0x400, size=0x10)])
        assert ReasonCodes.DATA_DIRECTORY_IN_HEADERS not in make_issue_list(issues)

    def test_in_headers_does_not_short_circuit(self):
        """
        Unlike the value checks, IN_HEADERS falls through - a directory can be
        in the headers AND unmapped.
        """
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section(va=0x2000, vs=0x100)],
                      data_directories=[_dir(rva=0x100, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_IN_HEADERS,
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]

    def test_missing_size_of_headers_skips_the_check(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x100, vs=0x1000)],
                      data_directories=[_dir(rva=0x200, size=0x10)])
        assert ReasonCodes.DATA_DIRECTORY_IN_HEADERS not in make_issue_list(issues)

    def test_out_of_range_flagged(self):
        issues = _run(_meta(size_of_image=0x200),
                      data_directories=[_dir(rva=0x150, size=0x100)])
        assert make_issue_list(issues) == [ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE]

    def test_end_exactly_at_size_of_image_not_flagged(self):
        """`rva + size > size_of_image` - the boundary is inclusive."""
        issues = _run(_meta(size_of_image=0x2000),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir(rva=0x1F00, size=0x100)])
        assert ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE not in make_issue_list(issues)

    def test_out_of_range_short_circuits_mapping(self):
        """`continue` after OUT_OF_RANGE suppresses overlay and mapping."""
        issues = _run(_meta(size_of_image=0x200),
                      sections=[_section(va=0x2000, vs=0x100)],
                      overlay_offset=0,
                      data_directories=[_dir(rva=0x150, size=0x100)])
        assert make_issue_list(issues) == [ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE]

    def test_in_headers_and_out_of_range_both_fire(self):
        issues = _run(_meta(size_of_image=0x200, size_of_headers=0x400),
                      data_directories=[_dir(rva=0x150, size=0x100)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_IN_HEADERS,
            ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE]


# =================================================================
# Raw mapping and overlay
# =================================================================

class TestRawMappingAndOverlay:

    def test_overlay_hit_flagged(self):
        issues = _run(_meta(),
                      overlay_offset=0x500,
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=0x400, raw_size=0x1000)],
                      data_directories=[_dir(rva=0x1200, size=0x10)])
        # raw_offset = 0x400 + 0x200 = 0x600 >= 0x500
        assert ReasonCodes.DATA_DIRECTORY_IN_OVERLAY in make_issue_list(issues)
        assert _details_for(
            issues, ReasonCodes.DATA_DIRECTORY_IN_OVERLAY)[0]["raw_offset"] == 0x600

    def test_raw_offset_exactly_at_overlay_flagged(self):
        """The comparison is `>=`."""
        issues = _run(_meta(),
                      overlay_offset=0x600,
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=0x400, raw_size=0x1000)],
                      data_directories=[_dir(rva=0x1200, size=0x10)])
        assert ReasonCodes.DATA_DIRECTORY_IN_OVERLAY in make_issue_list(issues)

    def test_raw_offset_below_overlay_not_flagged(self):
        issues = _run(_meta(),
                      overlay_offset=0x601,
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=0x400, raw_size=0x1000)],
                      data_directories=[_dir(rva=0x1200, size=0x10)])
        assert issues == []

    def test_missing_overlay_offset_skips_the_check(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=0x400, raw_size=0x1000)],
                      data_directories=[_dir(rva=0x1200, size=0x10)])
        assert issues == []

    def test_raw_mismatch_flagged(self):
        """
        The RVA maps into the section's VIRTUAL range but the derived raw
        offset falls outside its raw data - a virtual size larger than the
        raw size.
        """
        issues = _run(_meta(),
                      overlay_offset=0x9999,
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=0x400, raw_size=0x10)],
                      data_directories=[_dir(rva=0x1800, size=0x10)])
        assert ReasonCodes.DATA_DIRECTORY_RAW_MISMATCH in make_issue_list(issues)
        d = _details_for(issues, ReasonCodes.DATA_DIRECTORY_RAW_MISMATCH)[0]
        assert d["section_raw_start"] == 0x400
        assert d["section_raw_end"] == 0x410
        assert d["raw_offset"] == 0xC00

    def test_missing_raw_size_defaults_to_zero_and_mismatches(self):
        """
        FIXTURE TRAP: `sec.get("raw_size", 0)` means a section without
        raw_size has an empty raw range, so ANY directory mapping into it
        trips RAW_MISMATCH. Fixtures exercising overlay must set raw_size.
        """
        issues = _run(_meta(),
                      overlay_offset=0x300,
                      sections=[_section(va=0x100, vs=0x500,
                                         raw=0x200, raw_size=None)],
                      data_directories=[_dir(rva=0x250, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_RAW_MISMATCH,
            ReasonCodes.DATA_DIRECTORY_IN_OVERLAY]

    def test_missing_raw_address_breaks_and_skips_overlay(self):
        """
        A section with no raw_address cannot be mapped, so the loop breaks,
        raw_offset stays None and `continue` skips BOTH the overlay check and
        the later section-mapping checks.
        """
        issues = _run(_meta(),
                      overlay_offset=0x100,
                      sections=[_section(va=0x1000, vs=0x1000,
                                         raw=None, raw_size=0x200)],
                      data_directories=[_dir(rva=0x1000, size=0x100)])
        assert issues == []

    def test_unmapped_rva_is_flagged_regardless_of_overlay_offset(self):
        """
        A directory whose RVA maps to no section is reported as unmapped
        whether or not an overlay is present.

        Previously the `raw_offset is None` guard used a bare `continue`,
        which skipped the section-mapping checks entirely - so the presence of
        an unrelated overlay_offset silently suppressed
        NOT_MAPPED_TO_SECTION. The guard is now scoped to the overlay check.
        """
        with_overlay = _run(_meta(),
                            overlay_offset=0x100,
                            sections=[_section(va=0x1000, vs=0x100)],
                            data_directories=[_dir(rva=0x2000, size=0x10)])
        without_overlay = _run(_meta(),
                               sections=[_section(va=0x1000, vs=0x100)],
                               data_directories=[_dir(rva=0x2000, size=0x10)])

        assert make_issue_list(with_overlay) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]
        assert make_issue_list(without_overlay) == make_issue_list(with_overlay)

    def test_same_directory_without_overlay_offset_is_flagged_unmapped(self):
        """Control for the test above: the only difference is overlay_offset."""
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x100)],
                      data_directories=[_dir(rva=0x2000, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]

    def test_mismatching_section_continues_to_a_later_match(self):
        """
        On mismatch the loop `continue`s rather than breaking, so a second
        section covering the same VA can still resolve raw_offset. Only one
        mismatch is emitted and the resolved offset comes from the later
        section.
        """
        issues = _run(_meta(),
                      overlay_offset=0x9999,
                      sections=[
                          _section("A", 0x1000, 0x1000, raw=0x400, raw_size=0x10),
                          _section("B", 0x1000, 0x1000, raw=0x800, raw_size=0x1000),
                      ],
                      data_directories=[_dir(rva=0x1800, size=0x10)])
        codes = make_issue_list(issues)
        assert codes.count(ReasonCodes.DATA_DIRECTORY_RAW_MISMATCH) == 1
        assert ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS in codes


# =================================================================
# Section mapping
# =================================================================

class TestSectionMapping:

    def test_mapped_directory_is_silent(self):
        assert _run(_meta(),
                    sections=[_section(va=0x1000, vs=0x1000)],
                    data_directories=[_dir(rva=0x1000, size=0x100)]) == []

    def test_not_mapped_flagged(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x100, vs=0x100)],
                      data_directories=[_dir(rva=0x500, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]

    def test_no_sections_means_not_mapped(self):
        issues = _run(_meta(), data_directories=[_dir(rva=0x1000, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]

    def test_spans_multiple_sections_flagged(self):
        issues = _run(_meta(),
                      sections=[_section("A", 0x100, 0x100),
                                _section("B", 0x150, 0x100)],
                      data_directories=[_dir(rva=0x120, size=0x100)])
        assert ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS in make_issue_list(issues)
        assert _details_for(
            issues,
            ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS)[0]["sections"] == ["A", "B"]

    def test_exactly_one_section_is_silent(self):
        issues = _run(_meta(),
                      sections=[_section("A", 0x1000, 0x1000),
                                _section("B", 0x2000, 0x1000)],
                      data_directories=[_dir(rva=0x1000, size=0x100)])
        assert issues == []

    def test_overlap_uses_half_open_interval(self):
        """
        `rva < va_end and rva + size > va_start` - a directory ending exactly
        at a section start does not count as spanning it.
        """
        issues = _run(_meta(),
                      sections=[_section("A", 0x1000, 0x100),
                                _section("B", 0x1100, 0x100)],
                      data_directories=[_dir(rva=0x1000, size=0x100)])
        assert ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS not in make_issue_list(issues)

    def test_zero_length_section_hit_skips_mapping(self):
        """
        A directory whose RVA lands exactly on a zero-length section is
        skipped: it cannot be meaningfully mapped.
        """
        assert _run(_meta(),
                    sections=[_section(".empty", 0x1000, 0, raw=0x500)],
                    data_directories=[_dir(rva=0x1000, size=0x10)]) == []

    def test_zero_length_section_requires_exact_rva_match(self):
        """Landing near - not on - a zero-length section is still unmapped."""
        issues = _run(_meta(),
                      sections=[_section(".empty", 0x1000, 0, raw=0x500)],
                      data_directories=[_dir(rva=0x1004, size=0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION]

    def test_nonzero_length_section_at_same_rva_is_not_skipped(self):
        """
        Control: the skip needs BOTH va_start == rva AND vs == 0. A VA match
        alone must not skip.

        The fixture spans two sections so that skipping would be observable -
        a directory that simply maps cleanly emits nothing either way, and
        could not distinguish the two behaviours.
        """
        issues = _run(_meta(),
                      sections=[_section("A", 0x1000, 0x100),
                                _section("B", 0x1050, 0x100)],
                      data_directories=[_dir(rva=0x1000, size=0x100)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS]


# =================================================================
# Directory overlap
# =================================================================

class TestDirectoryOverlap:

    def test_overlapping_directories_flagged(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", 0x1000, 0x100),
                                        _dir("B", 0x1050, 0x100)])
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP in make_issue_list(issues)
        assert _details_for(issues, ReasonCodes.DATA_DIRECTORY_OVERLAP)[0] == {
            "directory_a": "A", "directory_b": "B"}

    def test_adjacent_directories_not_flagged(self):
        """`max(start) < min(end)` - touching ranges do not overlap."""
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", 0x1000, 0x100),
                                        _dir("B", 0x1100, 0x100)])
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(issues)

    def test_malformed_second_directory_skipped(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", 0x1000, 0x100),
                                        _dir("B", "bad", 0x100)])
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(issues)

    def test_malformed_first_directory_skipped(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", "bad", 0x100),
                                        _dir("B", 0x1000, 0x100)])
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in make_issue_list(issues)

    def test_each_overlapping_pair_reported_once(self):
        """Three mutually overlapping directories give C(3,2) = 3 pairs."""
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", 0x1000, 0x100),
                                        _dir("B", 0x1010, 0x100),
                                        _dir("C", 0x1020, 0x100)])
        pairs = [(d["directory_a"], d["directory_b"])
                 for d in _details_for(issues, ReasonCodes.DATA_DIRECTORY_OVERLAP)]
        assert pairs == [("A", "B"), ("A", "C"), ("B", "C")]

    def test_overlap_runs_even_for_directories_skipped_earlier(self):
        """
        The overlap pass is independent of the per-directory loop: a pair that
        was `continue`d there (zero size) is still compared here - and a
        zero-size range can never overlap, so it stays silent.
        """
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[_dir("A", 0x1000, 0),
                                        _dir("B", 0x1000, 0x100)])
        codes = make_issue_list(issues)
        assert ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA in codes
        assert ReasonCodes.DATA_DIRECTORY_OVERLAP not in codes

    def test_overlap_labelled_by_index_when_name_absent(self):
        issues = _run(_meta(),
                      sections=[_section(va=0x1000, vs=0x1000)],
                      data_directories=[{"index": 1, "rva": 0x1000, "size": 0x100},
                                        {"index": 2, "rva": 0x1050, "size": 0x100}])
        assert _details_for(issues, ReasonCodes.DATA_DIRECTORY_OVERLAP)[0] == {
            "directory_a": 1, "directory_b": 2}


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_dependency_contract(self):
        assert getattr(validate_rva_graph, "_depends_on") == ("metadata", "analysis")

    def test_returns_list(self):
        assert isinstance(_run(_meta(), data_directories=[_dir()]), list)

    def test_each_issue_has_issue_and_details(self):
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section(va=0x2000, vs=0x100)],
                      data_directories=[_dir(rva=0x100, size=0x10)])
        assert issues
        for issue in issues:
            assert set(issue) == {"issue", "details"}
            assert isinstance(issue["issue"], str)
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"]
        would overwrite the parent reason code. This validator uses no
        sub-reasons; the guard pins that none is introduced.
        """
        issues = _run(_meta(size_of_image=0x2000, size_of_headers=0x400),
                      overlay_offset=0x500,
                      sections=[_section("A", 0x1000, 0x1000,
                                         raw=0x400, raw_size=0x10)],
                      data_directories=[_dir("A", 0x100, 0x10),
                                        _dir("B", 0x1800, 0x10),
                                        _dir("C", 0x1800, 0x10),
                                        _dir("D", 0, 0x10),
                                        _dir("E", 0x1000, 0)])
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_json_serialisable(self):
        import json
        issues = _run(_meta(size_of_headers=0x400),
                      sections=[_section(va=0x2000, vs=0x100)],
                      data_directories=[_dir("A", 0x100, 0x10),
                                        _dir("B", 0x100, 0x10)])
        json.dumps(issues)   # must not raise

    def test_inputs_are_not_mutated(self):
        import copy
        metadata = _meta(size_of_headers=0x400)
        analysis = {
            "overlay_offset": 0x500,
            "sections": [_section("A", 0x1000, 0x1000, raw=0x400, raw_size=0x10)],
            "data_directories": [_dir("A", 0x1800, 0x10), _dir("B", 0x1800, 0x10)],
        }
        md_snapshot = copy.deepcopy(metadata)
        an_snapshot = copy.deepcopy(analysis)
        validate_rva_graph(metadata, analysis)
        assert metadata == md_snapshot
        assert analysis == an_snapshot


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_is_identical(self):
        import json
        metadata = _meta(size_of_image=0x2000, size_of_headers=0x400)
        analysis = {
            "overlay_offset": 0x500,
            "sections": [_section("A", 0x1000, 0x1000, raw=0x400, raw_size=0x10),
                         _section("B", 0x1800, 0x800, raw=0x800, raw_size=0x800)],
            "data_directories": [_dir("A", 0x100, 0x10), _dir("B", 0x1800, 0x10),
                                 _dir("C", 0x1800, 0x10), _dir("D", 0, 0x10)],
        }
        first = json.dumps(validate_rva_graph(metadata, analysis), sort_keys=True)
        for _ in range(20):
            assert json.dumps(validate_rva_graph(metadata, analysis),
                              sort_keys=True) == first

    def test_emission_order_is_directories_then_overlaps(self):
        """
        All per-directory issues are emitted first, in directory order; the
        overlap pass runs afterwards.
        """
        issues = _run(_meta(size_of_image=0x2000),
                      sections=[_section(va=0x1800, vs=0x800)],
                      data_directories=[_dir("A", 0x100, 0x10),
                                        _dir("B", 0x1800, 0x10),
                                        _dir("C", 0x1800, 0x10)])
        assert make_issue_list(issues) == [
            ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION,   # A
            ReasonCodes.DATA_DIRECTORY_OVERLAP,                  # B vs C
        ]
