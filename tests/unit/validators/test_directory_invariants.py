# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators._directory_invariants.

Pure-logic module (no PE object needed): the "analysis" input is a plain
dict, so every branch is driven directly. Covers:
  - region_within_image: None-guards, negative rva/size, in/out of bounds
  - _sections: key tolerance (rva/virtual_address, virtual_size/size),
    None-field skips, int() coercion, and the (ValueError, TypeError) except
  - rva_in_any_section: section hit/miss + SizeOfImage fallback + None
  - region_in_any_section: whole-region fit/miss + fallback + None

The tri-state contract (True / False / None) is asserted explicitly, since
callers rely on None meaning "unknown", not "out of bounds".

LAYER NOTE (important): SizeOfImage is passed as an EXPLICIT third/fourth
positional argument. These helpers deliberately do NOT read it from the
analysis dict - it does not live there. SizeOfImage is optional-header truth
(metadata["optional_header"]["size_of_image"]); the caller reads it from the
metadata layer and threads it in.

Historically the helpers did `analysis.get("size_of_image")`, which was always
None in production because the analysis layer never carries that key. The
fallback path was therefore dead on real files while these tests - which
supplied the key in the analysis dict - passed. The fixtures below keep
SizeOfImage strictly out of the analysis dict so that mismatch cannot recur.
"""

from __future__ import annotations

import pytest

from iocx.validators._directory_invariants import (
    region_within_image,
    rva_in_any_section,
    region_in_any_section,
    _sections,
)


# =================================================================
# region_within_image
# =================================================================

class TestRegionWithinImage:
    def test_none_rva_returns_none(self):
        assert region_within_image(None, 0x10, 0x1000) is None

    def test_none_size_of_image_returns_none(self):
        assert region_within_image(0x100, 0x10, None) is None

    def test_negative_rva_false(self):
        assert region_within_image(-1, 0x10, 0x1000) is False

    def test_negative_size_false(self):
        assert region_within_image(0x100, -1, 0x1000) is False

    def test_within_bounds_true(self):
        assert region_within_image(0x100, 0x10, 0x1000) is True

    def test_exact_end_boundary_true(self):
        # rva + size == size_of_image is inclusive (<=)
        assert region_within_image(0xFF0, 0x10, 0x1000) is True

    def test_one_past_end_false(self):
        assert region_within_image(0xFF0, 0x11, 0x1000) is False

    def test_none_size_treated_as_zero(self):
        # size None -> span 0; a bare rva within the image is True
        assert region_within_image(0x100, None, 0x1000) is True

    def test_zero_size_at_size_of_image_boundary_true(self):
        assert region_within_image(0x1000, 0, 0x1000) is True


# =================================================================
# _sections
# =================================================================

class TestSections:
    def test_empty_when_absent(self):
        assert _sections({}) == []

    def test_none_sections_value(self):
        assert _sections({"sections": None}) == []

    def test_rva_and_virtual_size_keys(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x200}]}
        assert _sections(analysis) == [(0x1000, 0x200)]

    def test_virtual_address_and_size_aliases(self):
        analysis = {"sections": [{"virtual_address": 0x2000, "size": 0x100}]}
        assert _sections(analysis) == [(0x2000, 0x100)]

    def test_missing_rva_skipped(self):
        analysis = {"sections": [{"virtual_size": 0x200}]}
        assert _sections(analysis) == []

    def test_missing_vsize_skipped(self):
        analysis = {"sections": [{"rva": 0x1000}]}
        assert _sections(analysis) == []

    def test_int_coercible_strings_coerced(self):
        analysis = {"sections": [{"rva": "4096", "virtual_size": "512"}]}
        assert _sections(analysis) == [(0x1000, 0x200)]

    def test_non_coercible_value_excepted_and_skipped(self):
        # int("nope") raises ValueError -> section skipped, others kept
        analysis = {"sections": [
            {"rva": "nope", "virtual_size": 0x200},
            {"rva": 0x3000, "virtual_size": 0x10},
        ]}
        assert _sections(analysis) == [(0x3000, 0x10)]

    def test_typeerror_value_excepted(self):
        # int(object()) raises TypeError -> skipped
        analysis = {"sections": [{"rva": object(), "virtual_size": 0x200}]}
        assert _sections(analysis) == []

    def test_multiple_sections_order_preserved(self):
        analysis = {"sections": [
            {"rva": 0x1000, "virtual_size": 0x100},
            {"rva": 0x2000, "virtual_size": 0x200},
        ]}
        assert _sections(analysis) == [(0x1000, 0x100), (0x2000, 0x200)]

    def test_production_section_shape_without_virtual_address(self):
        """
        The serialised analysis.sections shape carries name/raw_size/
        virtual_size/characteristics/entropy but NO virtual_address. Such a
        section yields no extent, so callers fall back to the SizeOfImage
        bound. Pinned so the dependency on virtual_address is explicit.
        """
        analysis = {"sections": [
            {"name": ".text", "raw_size": 512, "virtual_size": 4096,
             "characteristics": 0x60000020, "entropy": 0.0},
        ]}
        assert _sections(analysis) == []


# =================================================================
# rva_in_any_section
# =================================================================

class TestRvaInAnySection:
    def test_none_rva_returns_none(self):
        assert rva_in_any_section(None, {}, 0x1000) is None

    def test_hit_inside_section(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert rva_in_any_section(0x1500, analysis) is True

    def test_at_section_base_true(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert rva_in_any_section(0x1000, analysis) is True

    def test_at_section_end_exclusive_false(self):
        # base + vsize is exclusive
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert rva_in_any_section(0x2000, analysis) is False

    def test_miss_all_sections_false(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x10}]}
        assert rva_in_any_section(0x9000, analysis) is False

    def test_negative_vsize_clamped(self):
        # max(vsize, 0): a negative virtual_size yields an empty extent
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": -5}]}
        assert rva_in_any_section(0x1000, analysis) is False

    def test_fallback_within_size_of_image_true(self):
        # no sections -> SizeOfImage bound check (explicit 3rd argument)
        assert rva_in_any_section(0x500, {}, 0x1000) is True

    def test_fallback_out_of_size_of_image_false(self):
        assert rva_in_any_section(0x2000, {}, 0x1000) is False

    def test_no_sections_and_no_size_of_image_none(self):
        assert rva_in_any_section(0x500, {}) is None

    def test_empty_sections_list_uses_fallback(self):
        # [] is falsy -> fallback path, not the section loop
        assert rva_in_any_section(0x500, {"sections": []}, 0x1000) is True

    def test_size_of_image_in_analysis_is_ignored(self):
        """
        REGRESSION GUARD. SizeOfImage must come from the explicit argument.
        A stale analysis["size_of_image"] must NOT be consulted - if it were,
        this would return True and the production dead-path would be back.
        """
        assert rva_in_any_section(0x500, {"size_of_image": 0x1000}) is None

    def test_sections_take_precedence_over_size_of_image(self):
        """Section geometry is authoritative when present."""
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x10}]}
        # 0x9000 is inside SizeOfImage but outside every section
        assert rva_in_any_section(0x9000, analysis, 0x100000) is False


# =================================================================
# region_in_any_section
# =================================================================

class TestRegionInAnySection:
    def test_none_rva_returns_none(self):
        assert region_in_any_section(None, 0x10, {}, 0x1000) is None

    def test_whole_region_fits_true(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert region_in_any_section(0x1000, 0x100, analysis) is True

    def test_region_spilling_past_section_false(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x100}]}
        # region ends at 0x1200, section ends at 0x1100
        assert region_in_any_section(0x1000, 0x200, analysis) is False

    def test_region_at_exact_section_end_true(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x100}]}
        # rva+size == base+vsize (inclusive <=)
        assert region_in_any_section(0x1000, 0x100, analysis) is True

    def test_none_size_treated_as_zero(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x100}]}
        assert region_in_any_section(0x1050, None, analysis) is True

    def test_region_before_section_false(self):
        analysis = {"sections": [{"rva": 0x2000, "virtual_size": 0x100}]}
        assert region_in_any_section(0x1000, 0x10, analysis) is False

    def test_negative_vsize_clamped(self):
        # max(vsize, 0) makes the section a zero-length extent [0x1000, 0x1000).
        # A NON-zero region cannot fit -> False ...
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": -5}]}
        assert region_in_any_section(0x1000, 0x10, analysis) is False

    def test_zero_region_at_clamped_empty_section_true(self):
        # ... but a ZERO-length region at that base does "fit": end == base,
        # and 0x1000 <= 0x1000 and (0x1000 + 0) <= 0x1000. Documenting the
        # boundary explicitly so the behaviour is intentional, not accidental.
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": -5}]}
        assert region_in_any_section(0x1000, 0, analysis) is True

    def test_spans_two_sections_not_single_false(self):
        # region straddles the gap; no single section contains it
        analysis = {"sections": [
            {"rva": 0x1000, "virtual_size": 0x100},
            {"rva": 0x1100, "virtual_size": 0x100},
        ]}
        assert region_in_any_section(0x1080, 0x100, analysis) is False

    def test_fallback_within_size_of_image_true(self):
        assert region_in_any_section(0x100, 0x10, {}, 0x1000) is True

    def test_fallback_out_of_size_of_image_false(self):
        assert region_in_any_section(0xFF0, 0x100, {}, 0x1000) is False

    def test_no_sections_and_no_size_of_image_none(self):
        assert region_in_any_section(0x100, 0x10, {}) is None

    def test_empty_sections_list_uses_fallback(self):
        assert region_in_any_section(0x100, 0x10, {"sections": []},
                                     0x1000) is True

    def test_size_of_image_in_analysis_is_ignored(self):
        """
        REGRESSION GUARD - companion to the rva_in_any_section case above.
        """
        assert region_in_any_section(0x100, 0x10,
                                     {"size_of_image": 0x1000}) is None

    def test_sections_take_precedence_over_size_of_image(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x10}]}
        assert region_in_any_section(0x9000, 0x10, analysis, 0x100000) is False


# =================================================================
# Tri-state contract & purity
# =================================================================

class TestContract:
    def test_tri_state_values(self):
        # explicit True / False / None across the three public helpers
        secs = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert rva_in_any_section(0x1500, secs) is True
        assert rva_in_any_section(0x9000, secs) is False
        assert rva_in_any_section(None, secs) is None
        assert region_in_any_section(0x1000, 0x10, secs) is True
        assert region_in_any_section(0x9000, 0x10, secs) is False
        assert region_in_any_section(None, 0x10, secs) is None

    def test_tri_state_on_fallback_path(self):
        """
        The fallback path must express the same tri-state. Without this, the
        None case is only ever exercised via the section path.
        """
        assert rva_in_any_section(0x500, {}, 0x1000) is True
        assert rva_in_any_section(0x2000, {}, 0x1000) is False
        assert rva_in_any_section(0x500, {}) is None
        assert region_in_any_section(0x500, 0x10, {}, 0x1000) is True
        assert region_in_any_section(0x2000, 0x10, {}, 0x1000) is False
        assert region_in_any_section(0x500, 0x10, {}) is None

    def test_size_of_image_defaults_preserve_two_arg_call(self):
        """
        Back-compat: the SizeOfImage parameter is optional, so pre-existing
        two-/three-argument call sites keep working (degrading to None on the
        fallback path rather than raising).
        """
        secs = {"sections": [{"rva": 0x1000, "virtual_size": 0x1000}]}
        assert rva_in_any_section(0x1500, secs) is True
        assert region_in_any_section(0x1000, 0x10, secs) is True

    def test_no_mutation_of_analysis(self):
        analysis = {"sections": [{"rva": 0x1000, "virtual_size": 0x100}]}
        import copy
        snapshot = copy.deepcopy(analysis)
        rva_in_any_section(0x1050, analysis, 0x1000)
        region_in_any_section(0x1050, 0x10, analysis, 0x1000)
        region_within_image(0x100, 0x10, 0x1000)
        assert analysis == snapshot  # side-effect-free
