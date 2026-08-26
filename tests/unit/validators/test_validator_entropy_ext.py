# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.entropy.validate_entropy.

Layer note: the validator is @depends_on("metadata", "analysis") and takes TWO
positional arguments. It reads only the analysis layer; the metadata argument
is accepted but unused.

Threshold note: every check here is a numeric comparison against a module
constant, so the tests below pin the BOUNDARY (>= / <=) rather than just
asserting a code appears for an obviously-extreme value. Presence-only tests
cannot detect a threshold drifting by one, or a `>=` becoming `>`.

Float note: `stddev` is computed, so the UNIFORM_STDDEV_THRESHOLD boundary is
not cleanly testable at exactly 0.15 - two entropies whose spread is nominally
0.15 produce 0.15000000000000036 and fail the `<=`. The tests use values
clearly inside and outside the threshold and document the boundary rather than
asserting a flaky equality.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from iocx.validators.entropy import (
    validate_entropy,
    HIGH_ENTROPY_THRESHOLD,
    LOW_ENTROPY_THRESHOLD,
    MIN_SECTION_SIZE_FOR_ENTROPY,
    MIN_SECTION_SIZE_FOR_LOW_ENTROPY,
    MIN_OVERLAY_SIZE_FOR_ENTROPY,
    UNIFORM_STDDEV_THRESHOLD,
)
from iocx.reason_codes import ReasonCodes


# =================================================================
# Helpers
# =================================================================

def _section(name: str = ".text", entropy: Any = 5.0,
             raw_size: Any = 2000) -> Dict[str, Any]:
    return {"name": name, "entropy": entropy, "raw_size": raw_size}


def _run(**analysis) -> List[Dict[str, Any]]:
    return validate_entropy({}, analysis)


def make_issue_list(result) -> List[str]:
    return [i["issue"] for i in result]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# Input tolerance
# =================================================================

class TestInputTolerance:

    def test_missing_sections_key(self):
        assert _run() == []

    def test_none_sections_value(self):
        assert _run(sections=None) == []

    def test_empty_sections_list(self):
        assert _run(sections=[]) == []

    @pytest.mark.parametrize("entropy", ["bad", None, [], {}])
    def test_non_numeric_entropy_skipped(self, entropy):
        assert _run(sections=[_section(entropy=entropy)]) == []

    @pytest.mark.parametrize("raw_size", ["bad", None, 2000.5, []])
    def test_non_int_raw_size_skipped(self, raw_size):
        """raw_size must be an int - a float is rejected, not coerced."""
        assert _run(sections=[_section(entropy=8.0, raw_size=raw_size)]) == []

    def test_bool_entropy_accepted_as_numeric(self):
        """
        bool is a subclass of int, so isinstance(True, (int, float)) passes.
        Documents the behaviour rather than asserting it is desirable.
        """
        issues = _run(sections=[_section(entropy=True, raw_size=20000)])
        # True -> 1.0, which is above LOW and below HIGH, so nothing fires
        assert issues == []

    def test_missing_name_defaults_to_empty_string(self):
        issues = _run(sections=[{"entropy": 8.0, "raw_size": 2000}])
        assert _details_for(issues, ReasonCodes.ENTROPY_HIGH_SECTION)[0]["section"] == ""

    def test_none_name_defaults_to_empty_string(self):
        issues = _run(sections=[_section(name=None, entropy=8.0)])
        assert _details_for(issues, ReasonCodes.ENTROPY_HIGH_SECTION)[0]["section"] == ""

    def test_int_entropy_converted_to_float(self):
        issues = _run(sections=[_section(entropy=8, raw_size=2000)])
        d = _details_for(issues, ReasonCodes.ENTROPY_HIGH_SECTION)[0]
        assert isinstance(d["entropy"], float)
        assert d["entropy"] == 8.0


# =================================================================
# High-entropy sections
# =================================================================

class TestHighEntropySection:

    def test_high_entropy_flagged(self):
        issues = _run(sections=[_section(entropy=8.0)])
        assert make_issue_list(issues) == [ReasonCodes.ENTROPY_HIGH_SECTION]

    def test_entropy_exactly_at_threshold_flagged(self):
        """The comparison is `>=`, so the threshold itself fires."""
        issues = _run(sections=[_section(entropy=HIGH_ENTROPY_THRESHOLD)])
        assert ReasonCodes.ENTROPY_HIGH_SECTION in make_issue_list(issues)

    def test_entropy_just_below_threshold_not_flagged(self):
        issues = _run(sections=[_section(entropy=HIGH_ENTROPY_THRESHOLD - 0.01)])
        assert issues == []

    def test_size_exactly_at_minimum_flagged(self):
        issues = _run(sections=[
            _section(entropy=8.0, raw_size=MIN_SECTION_SIZE_FOR_ENTROPY)])
        assert ReasonCodes.ENTROPY_HIGH_SECTION in make_issue_list(issues)

    def test_size_just_below_minimum_not_flagged(self):
        """
        Small sections are excluded entirely - a 1023-byte section with
        entropy 8.0 is not reported, and is also absent from the uniform
        sample.
        """
        issues = _run(sections=[
            _section(entropy=8.0, raw_size=MIN_SECTION_SIZE_FOR_ENTROPY - 1)])
        assert issues == []

    def test_details_payload(self):
        issues = _run(sections=[_section(".upx0", 7.9, 4096)])
        assert _details_for(issues, ReasonCodes.ENTROPY_HIGH_SECTION)[0] == {
            "section": ".upx0", "entropy": 7.9, "raw_size": 4096}

    def test_each_high_section_flagged_separately(self):
        issues = _run(sections=[_section(".a", 8.0), _section(".b", 8.1)])
        high = _details_for(issues, ReasonCodes.ENTROPY_HIGH_SECTION)
        assert [d["section"] for d in high] == [".a", ".b"]


# =================================================================
# Very-low-entropy sections
# =================================================================

class TestVeryLowEntropySection:

    def test_very_low_entropy_flagged(self):
        issues = _run(sections=[_section(entropy=0.1, raw_size=20000)])
        assert make_issue_list(issues) == [ReasonCodes.ENTROPY_VERY_LOW_SECTION]

    def test_entropy_exactly_at_threshold_flagged(self):
        """The comparison is `<=`, so the threshold itself fires."""
        issues = _run(sections=[
            _section(entropy=LOW_ENTROPY_THRESHOLD, raw_size=20000)])
        assert ReasonCodes.ENTROPY_VERY_LOW_SECTION in make_issue_list(issues)

    def test_entropy_just_above_threshold_not_flagged(self):
        issues = _run(sections=[
            _section(entropy=LOW_ENTROPY_THRESHOLD + 0.01, raw_size=20000)])
        assert issues == []

    def test_size_exactly_at_low_minimum_flagged(self):
        issues = _run(sections=[
            _section(entropy=0.1, raw_size=MIN_SECTION_SIZE_FOR_LOW_ENTROPY)])
        assert ReasonCodes.ENTROPY_VERY_LOW_SECTION in make_issue_list(issues)

    def test_size_just_below_low_minimum_not_flagged(self):
        """
        The low-entropy check uses a much larger minimum (16 KB) than the high
        check (1 KB): a 16383-byte zero-filled section is deliberately ignored.
        """
        issues = _run(sections=[
            _section(entropy=0.1,
                     raw_size=MIN_SECTION_SIZE_FOR_LOW_ENTROPY - 1)])
        assert issues == []

    def test_low_and_high_minimums_are_different(self):
        """
        Pin the asymmetry: a section between the two minimums participates in
        the high check and the uniform sample, but never the low check.
        """
        assert MIN_SECTION_SIZE_FOR_LOW_ENTROPY > MIN_SECTION_SIZE_FOR_ENTROPY
        issues = _run(sections=[_section(entropy=0.0, raw_size=2000)])
        assert issues == []

    def test_details_payload(self):
        issues = _run(sections=[_section(".bss", 0.03, 32768)])
        assert _details_for(issues, ReasonCodes.ENTROPY_VERY_LOW_SECTION)[0] == {
            "section": ".bss", "entropy": 0.03, "raw_size": 32768}

    def test_high_and_low_are_mutually_exclusive(self):
        """No entropy value can satisfy both thresholds."""
        assert LOW_ENTROPY_THRESHOLD < HIGH_ENTROPY_THRESHOLD


# =================================================================
# Overlay entropy
# =================================================================

class TestOverlayEntropy:

    def test_high_overlay_flagged(self):
        issues = _run(sections=[], overlay={"entropy": 8.0, "size": 2000})
        assert make_issue_list(issues) == [ReasonCodes.ENTROPY_HIGH_OVERLAY]

    def test_entropy_exactly_at_threshold_flagged(self):
        issues = _run(sections=[],
                      overlay={"entropy": HIGH_ENTROPY_THRESHOLD, "size": 2000})
        assert ReasonCodes.ENTROPY_HIGH_OVERLAY in make_issue_list(issues)

    def test_entropy_just_below_threshold_not_flagged(self):
        issues = _run(sections=[],
                      overlay={"entropy": HIGH_ENTROPY_THRESHOLD - 0.01,
                               "size": 2000})
        assert issues == []

    def test_size_exactly_at_minimum_flagged(self):
        issues = _run(sections=[],
                      overlay={"entropy": 8.0,
                               "size": MIN_OVERLAY_SIZE_FOR_ENTROPY})
        assert ReasonCodes.ENTROPY_HIGH_OVERLAY in make_issue_list(issues)

    def test_size_just_below_minimum_not_flagged(self):
        issues = _run(sections=[],
                      overlay={"entropy": 8.0,
                               "size": MIN_OVERLAY_SIZE_FOR_ENTROPY - 1})
        assert issues == []

    @pytest.mark.parametrize("overlay", [None, "not-a-dict", [], 42])
    def test_non_dict_overlay_skipped(self, overlay):
        assert _run(sections=[], overlay=overlay) == []

    def test_missing_overlay_key_skipped(self):
        assert _run(sections=[]) == []

    @pytest.mark.parametrize("entropy,size", [
        ("bad", 2000), (8.0, "bad"), (None, 2000), (8.0, None),
    ])
    def test_malformed_overlay_fields_skipped(self, entropy, size):
        assert _run(sections=[],
                    overlay={"entropy": entropy, "size": size}) == []

    def test_details_payload(self):
        issues = _run(sections=[], overlay={"entropy": 7.85, "size": 4096})
        assert _details_for(issues, ReasonCodes.ENTROPY_HIGH_OVERLAY)[0] == {
            "entropy": 7.85, "size": 4096}

    def test_overlay_does_not_join_the_uniform_sample(self):
        """
        Only sections feed `entropies`; a high overlay must not make a
        single-section file look uniform.
        """
        issues = _run(sections=[_section(entropy=7.6)],
                      overlay={"entropy": 7.6, "size": 2000})
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)


# =================================================================
# Region entropy
# =================================================================

class TestRegionEntropy:

    REGIONS = [
        ("resources", ReasonCodes.ENTROPY_HIGH_RESOURCES),
        ("relocations", ReasonCodes.ENTROPY_HIGH_RELOCATIONS),
        ("imports", ReasonCodes.ENTROPY_HIGH_IMPORTS),
        ("tls", ReasonCodes.ENTROPY_HIGH_TLS),
        ("certificate", ReasonCodes.ENTROPY_HIGH_CERTIFICATE),
    ]

    @pytest.mark.parametrize("region,reason", REGIONS)
    def test_each_region_maps_to_its_own_code(self, region, reason):
        issues = _run(region_entropy={region: {"entropy": 8.0, "size": 2000}})
        assert make_issue_list(issues) == [reason]

    @pytest.mark.parametrize("region,reason", REGIONS)
    def test_region_threshold_boundary(self, region, reason):
        at = _run(region_entropy={
            region: {"entropy": HIGH_ENTROPY_THRESHOLD, "size": 2000}})
        below = _run(region_entropy={
            region: {"entropy": HIGH_ENTROPY_THRESHOLD - 0.01, "size": 2000}})
        assert reason in make_issue_list(at)
        assert below == []

    @pytest.mark.parametrize("region,reason", REGIONS)
    def test_region_size_boundary(self, region, reason):
        at = _run(region_entropy={
            region: {"entropy": 8.0, "size": MIN_SECTION_SIZE_FOR_ENTROPY}})
        below = _run(region_entropy={
            region: {"entropy": 8.0, "size": MIN_SECTION_SIZE_FOR_ENTROPY - 1}})
        assert reason in make_issue_list(at)
        assert below == []

    def test_all_regions_can_fire_together(self):
        issues = _run(region_entropy={
            r: {"entropy": 8.0, "size": 2000} for r, _ in self.REGIONS})
        assert set(make_issue_list(issues)) == {c for _, c in self.REGIONS}

    def test_emission_order_follows_region_map(self):
        """Dict literal order is insertion order, so emission is deterministic."""
        issues = _run(region_entropy={
            r: {"entropy": 8.0, "size": 2000} for r, _ in reversed(self.REGIONS)})
        assert make_issue_list(issues) == [c for _, c in self.REGIONS]

    def test_region_below_threshold_continues_to_next_region(self):
        """
        A region present but under threshold must not emit, and must not stop
        later regions being evaluated (the loop-back branch).
        """
        issues = _run(region_entropy={
            "resources": {"entropy": 1.0, "size": 2000},   # below threshold
            "tls": {"entropy": 8.0, "size": 2000},         # above
        })
        assert make_issue_list(issues) == [ReasonCodes.ENTROPY_HIGH_TLS]

    def test_unknown_region_ignored(self):
        assert _run(region_entropy={"bogus": {"entropy": 8.0, "size": 2000}}) == []

    @pytest.mark.parametrize("value", [None, "not-a-dict", [], 42])
    def test_non_dict_region_info_skipped(self, value):
        assert _run(region_entropy={"resources": value}) == []

    @pytest.mark.parametrize("entropy,size", [
        ("bad", 2000), (8.0, "bad"), (None, 2000), (8.0, None), (8.0, 2000.5),
    ])
    def test_malformed_region_fields_skipped(self, entropy, size):
        """
        The info dict is present but its fields fail the type check. The loop
        must continue to the next region rather than emitting or raising.
        """
        issues = _run(region_entropy={
            "resources": {"entropy": entropy, "size": size},
            "tls": {"entropy": 8.0, "size": 2000},
        })
        assert make_issue_list(issues) == [ReasonCodes.ENTROPY_HIGH_TLS]

    def test_missing_region_entropy_key(self):
        assert _run(sections=[]) == []

    def test_none_region_entropy_value(self):
        assert _run(region_entropy=None) == []

    def test_details_payload(self):
        issues = _run(region_entropy={"tls": {"entropy": 7.7, "size": 8192}})
        assert _details_for(issues, ReasonCodes.ENTROPY_HIGH_TLS)[0] == {
            "entropy": 7.7, "size": 8192}

    def test_region_does_not_join_the_uniform_sample(self):
        issues = _run(sections=[_section(entropy=7.6)],
                      region_entropy={"resources": {"entropy": 7.6,
                                                    "size": 2000}})
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)


# =================================================================
# Uniform entropy across sections
# =================================================================

class TestUniformEntropy:
    """
    Requires BOTH mean >= HIGH_ENTROPY_THRESHOLD and
    stddev <= UNIFORM_STDDEV_THRESHOLD, over sections large enough to have
    joined the sample.
    """

    def test_uniform_high_entropy_flagged(self):
        issues = _run(sections=[
            _section(".text", 7.60), _section(".data", 7.62),
            _section(".rdata", 7.58)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(issues)

    def test_requires_at_least_two_sections(self):
        issues = _run(sections=[_section(".text", 7.6)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)

    def test_two_sections_is_enough(self):
        issues = _run(sections=[_section(".a", 7.6), _section(".b", 7.61)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(issues)

    def test_mean_just_below_threshold_not_flagged(self):
        """Identical entropies give stddev 0, so only the mean gate applies."""
        e = HIGH_ENTROPY_THRESHOLD - 0.01
        issues = _run(sections=[_section(".a", e), _section(".b", e)])
        assert issues == []

    def test_mean_exactly_at_threshold_flagged(self):
        e = HIGH_ENTROPY_THRESHOLD
        issues = _run(sections=[_section(".a", e), _section(".b", e)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(issues)

    def test_stddev_clearly_inside_threshold_flagged(self):
        """
        Spread of 0.14 -> stddev 0.14, comfortably inside 0.15.

        The exact boundary is NOT asserted: a nominal spread of 0.15 computes
        as 0.15000000000000036 and fails the `<=`. Testing equality there
        would pin float error rather than intent.
        """
        issues = _run(sections=[_section(".a", 7.60), _section(".b", 7.88)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(issues)

    def test_stddev_clearly_outside_threshold_not_flagged(self):
        issues = _run(sections=[_section(".a", 7.6), _section(".b", 8.0)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)

    def test_low_outlier_defeats_uniformity_via_mean(self):
        """
        A single low section drags the mean below the gate, so the check
        short-circuits before stddev is even considered. This is why a mixed
        fixture does not report uniformity.
        """
        issues = _run(sections=[
            _section(".a", 8.0), _section(".b", 0.1, 20000),
            _section(".c", 7.6)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)

    def test_small_sections_excluded_from_the_sample(self):
        """
        A sub-1 KB section never joins `entropies`, so it can neither trigger
        nor prevent uniformity.
        """
        with_small = _run(sections=[
            _section(".a", 7.6), _section(".b", 7.61),
            _section(".tiny", 0.0, 512)])
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(with_small)

    def test_two_small_sections_cannot_reach_the_gate(self):
        issues = _run(sections=[
            _section(".a", 7.6, 512), _section(".b", 7.61, 512)])
        assert issues == []

    def test_details_payload_reports_computed_statistics(self):
        issues = _run(sections=[_section(".a", 7.60), _section(".b", 7.62)])
        d = _details_for(issues,
                         ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS)[0]
        assert d["count"] == 2
        assert d["mean_entropy"] == pytest.approx(7.61)
        assert d["stddev_entropy"] == pytest.approx(0.01)

    def test_population_stddev_not_sample_stddev(self):
        """
        Variance divides by N, not N-1. For [7.5, 7.9] that is 0.2, not the
        0.2828 a sample stddev would give - which would fail the threshold and
        change the verdict.
        """
        issues = _run(sections=[_section(".a", 7.5), _section(".b", 7.9)])
        # population stddev 0.2 > 0.15, so no uniformity
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in make_issue_list(issues)
        # and the co-fired high sections confirm both were in the sample
        assert make_issue_list(issues).count(ReasonCodes.ENTROPY_HIGH_SECTION) == 2

    def test_uniform_co_fires_with_per_section_high(self):
        """
        Uniformly high sections trip BOTH the per-section code (once each) and
        the aggregate code - they are independent facts.
        """
        issues = _run(sections=[_section(".a", 7.6), _section(".b", 7.62)])
        codes = make_issue_list(issues)
        assert codes.count(ReasonCodes.ENTROPY_HIGH_SECTION) == 2
        assert codes.count(ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS) == 1


# =================================================================
# Combined scenarios
# =================================================================

class TestCombinedScenarios:

    def test_clean_file_emits_nothing(self):
        issues = _run(sections=[_section(".text", 5.0), _section(".data", 4.0)])
        assert issues == []

    def test_all_independent_paths_can_fire_together(self):
        issues = _run(
            sections=[_section(".text", 8.0), _section(".data", 0.1, 20000)],
            overlay={"entropy": 8.0, "size": 2000},
            region_entropy={"resources": {"entropy": 8.0, "size": 2000}},
        )
        codes = set(make_issue_list(issues))
        assert codes == {
            ReasonCodes.ENTROPY_HIGH_SECTION,
            ReasonCodes.ENTROPY_VERY_LOW_SECTION,
            ReasonCodes.ENTROPY_HIGH_OVERLAY,
            ReasonCodes.ENTROPY_HIGH_RESOURCES,
        }

    def test_packed_binary_profile(self):
        """A UPX-like image: uniformly high sections plus a high overlay."""
        issues = _run(
            sections=[_section(".upx0", 7.90, 4096),
                      _section(".upx1", 7.95, 8192)],
            overlay={"entropy": 7.99, "size": 4096},
        )
        codes = make_issue_list(issues)
        assert codes.count(ReasonCodes.ENTROPY_HIGH_SECTION) == 2
        assert ReasonCodes.ENTROPY_HIGH_OVERLAY in codes
        assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in codes


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_dependency_contract(self):
        assert getattr(validate_entropy, "_depends_on") == ("metadata", "analysis")

    def test_returns_list(self):
        assert isinstance(_run(sections=[_section()]), list)

    def test_each_issue_has_issue_and_details(self):
        issues = _run(sections=[_section(entropy=8.0)],
                      overlay={"entropy": 8.0, "size": 2000})
        for issue in issues:
            assert set(issue) == {"issue", "details"}
            assert isinstance(issue["issue"], str)
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"] would
        overwrite the parent reason code. This validator uses no sub-reasons,
        so the guard simply pins that none is ever introduced.
        """
        issues = _run(
            sections=[_section(".a", 8.0), _section(".b", 0.1, 20000),
                      _section(".c", 7.9)],
            overlay={"entropy": 8.0, "size": 2000},
            region_entropy={"resources": {"entropy": 8.0, "size": 2000}},
        )
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_json_serialisable(self):
        import json
        issues = _run(
            sections=[_section(".a", 7.6), _section(".b", 7.62)],
            overlay={"entropy": 8.0, "size": 2000},
            region_entropy={"imports": {"entropy": 8.0, "size": 2000}},
        )
        json.dumps(issues)   # must not raise

    def test_analysis_is_not_mutated(self):
        import copy
        analysis = {
            "sections": [_section(".a", 8.0), _section(".b", 7.6)],
            "overlay": {"entropy": 8.0, "size": 2000},
            "region_entropy": {"tls": {"entropy": 8.0, "size": 2000}},
        }
        snapshot = copy.deepcopy(analysis)
        validate_entropy({}, analysis)
        assert analysis == snapshot

    def test_metadata_argument_is_unused(self):
        """
        The validator declares a metadata dependency but reads nothing from
        it. Pin that, so a future change that starts using it is a conscious
        one.
        """
        sections = [_section(entropy=8.0)]
        assert validate_entropy({}, {"sections": sections}) == \
            validate_entropy({"optional_header": {"size_of_image": 0x1000}},
                             {"sections": sections})


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_is_identical(self):
        import json
        analysis = {
            "sections": [_section(".a", 8.0), _section(".b", 0.1, 20000),
                         _section(".c", 7.6)],
            "overlay": {"entropy": 8.0, "size": 2000},
            "region_entropy": {r: {"entropy": 8.0, "size": 2000}
                               for r in ("resources", "tls", "imports")},
        }
        first = json.dumps(validate_entropy({}, analysis), sort_keys=True)
        for _ in range(20):
            assert json.dumps(validate_entropy({}, analysis),
                              sort_keys=True) == first

    def test_emission_order_is_stable(self):
        """Sections first (in order), then overlay, then regions, then uniform."""
        issues = _run(
            sections=[_section(".a", 7.6), _section(".b", 7.62)],
            overlay={"entropy": 8.0, "size": 2000},
            region_entropy={"resources": {"entropy": 8.0, "size": 2000}},
        )
        assert make_issue_list(issues) == [
            ReasonCodes.ENTROPY_HIGH_SECTION,
            ReasonCodes.ENTROPY_HIGH_SECTION,
            ReasonCodes.ENTROPY_HIGH_OVERLAY,
            ReasonCodes.ENTROPY_HIGH_RESOURCES,
            ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS,
        ]
