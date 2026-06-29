# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Covers the entropy_min / entropy_max / entropy_avg computation introduced
during the extended.py refactor, which handles per-resource error tombstones
(entropy: None) without raising on min() / max() of an empty sequence.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
import pytest
from iocx.analysis.extended import analyse_extended


# =================================================================
# Test helpers
# =================================================================

def _resource(
    type_: str = "RT_RCDATA",
    name: Optional[str] = None,
    language: Optional[int] = 1033,
    language_name: Optional[str] = "en-US",
    codepage: Optional[int] = None,
    size: Optional[int] = 100,
    entropy: Optional[float] = 4.5,
    rva: int = 0x1000,
    raw_offset: Optional[int] = 0x400,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a resource entry dict matching the public ResourceEntry shape."""
    return {
        "type": type_,
        "name": name,
        "language": language,
        "language_name": language_name,
        "codepage": codepage,
        "size": size,
        "entropy": entropy,
        "rva": rva,
        "raw_offset": raw_offset,
        "errors": errors,
    }


def _metadata_with_resources(resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a minimal metadata dict containing only the resources field."""
    return {
        "import_details": [],
        "delayed_imports": [],
        "bound_imports": [],
        "exports": [],
        "resources": resources,
        "tls": None,
        "signatures": [],
        "header": {},
        "optional_header": None,
        "rich_header": None,
    }


def _resource_summary(detections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extract the resource-summary detection from the analyser output."""
    for d in detections:
        if d["value"] == "resources":
            return d["metadata"]
    return None


# =================================================================
# Happy path: all entropies present
# =================================================================

class TestAllEntropiesPresent:

    def test_single_resource_min_max_avg_equal(self):
        resources = [_resource(entropy=4.5)]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary is not None
        assert summary["count"] == 1
        assert summary["entropy_min"] == 4.5
        assert summary["entropy_max"] == 4.5
        assert summary["entropy_avg"] == 4.5

    def test_multiple_resources_computes_stats(self):
        resources = [
            _resource(type_="RT_ICON", entropy=2.0, rva=0x1000),
            _resource(type_="RT_STRING", entropy=4.0, rva=0x2000),
            _resource(type_="RT_VERSION", entropy=6.0, rva=0x3000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["count"] == 3
        assert summary["entropy_min"] == 2.0
        assert summary["entropy_max"] == 6.0
        assert summary["entropy_avg"] == 4.0

    def test_entropy_avg_handles_floating_point_precision(self):
        # Three values whose average is a repeating decimal
        resources = [
            _resource(entropy=1.0, rva=0x1000),
            _resource(entropy=2.0, rva=0x2000),
            _resource(entropy=2.0, rva=0x3000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        # 5.0 / 3 == 1.6666...
        assert summary["entropy_avg"] == pytest.approx(5.0 / 3)


# =================================================================
# Mixed: some entries have entropy None due to per-entry errors
# =================================================================

class TestMixedValidAndNoneEntropies:

    def test_excludes_none_entries_from_aggregates(self):
        resources = [
            _resource(type_="RT_ICON", entropy=3.0, rva=0x1000),
            _resource(
                type_="RT_STRING",
                entropy=None,
                size=None,
                rva=0x2000,
                errors=["size_invalid"],
            ),
            _resource(type_="RT_VERSION", entropy=5.0, rva=0x3000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)

        # count reflects total resources (including the error one)
        assert summary["count"] == 3

        # entropy stats compute over only the valid two
        assert summary["entropy_min"] == 3.0
        assert summary["entropy_max"] == 5.0
        assert summary["entropy_avg"] == 4.0

    def test_single_valid_entropy_among_errors(self):
        resources = [
            _resource(entropy=None, rva=0x1000, errors=["data_out_of_bounds"]),
            _resource(entropy=7.5, rva=0x2000),
            _resource(entropy=None, rva=0x3000, errors=["rva_invalid"]),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["count"] == 3
        assert summary["entropy_min"] == 7.5
        assert summary["entropy_max"] == 7.5
        assert summary["entropy_avg"] == 7.5

    def test_types_field_includes_error_entries(self):
        """The types list is built over all resources, not just valid-entropy ones."""
        resources = [
            _resource(type_="RT_ICON", entropy=3.0, rva=0x1000),
            _resource(type_="RT_CUSTOM", entropy=None, rva=0x2000, errors=["size_invalid"]),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert "RT_ICON" in summary["types"]
        assert "RT_CUSTOM" in summary["types"]


# =================================================================
# All entries have entropy None: aggregates must be None
# =================================================================

class TestAllEntropiesNone:

    def test_all_errored_resources_produce_none_stats(self):
        resources = [
            _resource(entropy=None, rva=0x1000, errors=["size_invalid"]),
            _resource(entropy=None, rva=0x2000, errors=["data_out_of_bounds"]),
            _resource(entropy=None, rva=0x3000, errors=["rva_invalid"]),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["count"] == 3
        assert summary["entropy_min"] is None
        assert summary["entropy_max"] is None
        assert summary["entropy_avg"] is None

    def test_single_errored_resource_produces_none_stats(self):
        resources = [
            _resource(entropy=None, rva=0x1000, errors=["size_invalid"]),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["count"] == 1
        assert summary["entropy_min"] is None
        assert summary["entropy_max"] is None
        assert summary["entropy_avg"] is None

    def test_no_raise_on_all_none_entropies(self):
        """
        Regression guard: previous implementation would have raised
        ValueError on min() / max() of an empty list.
        """
        resources = [_resource(entropy=None, errors=["size_invalid"])]
        # Must not raise
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        assert _resource_summary(detections) is not None


# =================================================================
# Empty resources list: summary block is omitted
# =================================================================

class TestEmptyResources:

    def test_empty_resources_produces_no_summary(self):
        """
        When the resources list is empty, the resource summary detection
        is not emitted at all (per the `if resources:` guard).
        """
        detections = analyse_extended(None, _metadata_with_resources([]), [])
        assert _resource_summary(detections) is None


# =================================================================
# Edge cases: zero and extreme entropy values
# =================================================================

class TestEntropyEdgeValues:

    def test_zero_entropy_included_in_stats(self):
        """
        Entropy of exactly 0.0 (all-zero resource bytes) is a valid value,
        not a missing-value sentinel. Must be included in aggregates.
        """
        resources = [
            _resource(entropy=0.0, rva=0x1000),
            _resource(entropy=4.0, rva=0x2000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["entropy_min"] == 0.0
        assert summary["entropy_max"] == 4.0
        assert summary["entropy_avg"] == 2.0

    def test_max_entropy_included_in_stats(self):
        """
        Entropy at the Shannon upper bound (8.0 for byte data) is valid.
        """
        resources = [
            _resource(entropy=8.0, rva=0x1000),
            _resource(entropy=4.0, rva=0x2000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["entropy_min"] == 4.0
        assert summary["entropy_max"] == 8.0
        assert summary["entropy_avg"] == 6.0

    def test_all_zero_entropies(self):
        """All-zero entropies still produce sensible stats."""
        resources = [
            _resource(entropy=0.0, rva=0x1000),
            _resource(entropy=0.0, rva=0x2000),
        ]
        detections = analyse_extended(None, _metadata_with_resources(resources), [])
        summary = _resource_summary(detections)
        assert summary["entropy_min"] == 0.0
        assert summary["entropy_max"] == 0.0
        assert summary["entropy_avg"] == 0.0


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_invocation_produces_identical_stats(self):
        resources = [
            _resource(entropy=3.1, rva=0x1000),
            _resource(entropy=None, rva=0x2000, errors=["size_invalid"]),
            _resource(entropy=5.7, rva=0x3000),
            _resource(entropy=2.4, rva=0x4000),
        ]
        metadata = _metadata_with_resources(resources)

        results = [analyse_extended(None, metadata, []) for _ in range(20)]
        summaries = [_resource_summary(r) for r in results]
        for s in summaries[1:]:
            assert s == summaries[0]
