# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Coverage-gap tests for iocx.validators.tls.validate_tls.

Targets the branches the main suite missed:
  - 130       callback-array truncation loop body (TLS_DIRECTORY_TRUNCATED)
  - 201       cascade early-return when ImageBase is not an int
  - 263       resolution-tombstone loop body (TLS_CALLBACK_RVA_INVALID)
  - 277-282   callbacks present but ImageBase not int (image_base_unavailable)
  - 287       `continue` when a callback VA is not an int
  - 293       resolved callback target that does not map to any section

Each fixture is shaped to reach exactly one target while keeping the rest of
the validator quiet, so the assertions stay unambiguous.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.tls import validate_tls


# =================================================================
# Builders
# =================================================================

def _tls(**kw) -> Dict[str, Any]:
    """A tls_struct with sensible, quiet defaults; override per test."""
    base: Dict[str, Any] = {
        "rva": 0x1000, "size": 24, "is_64bit": False, "image_base": 0x400000,
        "start_address_of_raw_data": None,
        "end_address_of_raw_data": None,
        "address_of_index": 0,
        "address_of_callbacks": None,
        "size_of_zero_fill": 0, "characteristics": 0,
        "raw_data_size": None,
        "callbacks": [], "callback_count": 0,
        "truncations": [], "errors": [],
    }
    base.update(kw)
    return base


def _run(tls: Optional[Dict[str, Any]],
         analysis: Optional[Dict[str, Any]] = None,
         metadata: Optional[Dict[str, Any]] = None):
    return validate_tls(
        {"tls_struct": tls},
        metadata or {},
        analysis if analysis is not None else {"extended": []},
    )


def _codes(issues) -> List:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


# =================================================================
# 130 — callback-array truncation loop body
# =================================================================

class TestCallbackArrayTruncation:
    def test_truncation_tag_emits_directory_truncated(self):
        # No header-decode error (that would short-circuit at step 2), a
        # truncations tag present -> line 130 loop body runs.
        tls = _tls(truncations=["tls_callbacks_truncated"])
        issues = _run(tls)
        assert ReasonCodes.TLS_DIRECTORY_TRUNCATED in _codes(issues)
        assert _details_for(issues, ReasonCodes.TLS_DIRECTORY_TRUNCATED) == [
            {"reason": "callback_array", "region": "tls_callbacks_truncated"}]

    def test_multiple_truncation_tags_in_order(self):
        tls = _tls(truncations=["tls_callbacks_read_failed",
                                "tls_callbacks_max_exceeded"])
        issues = _run(tls)
        regions = [d["region"] for d in
                   _details_for(issues, ReasonCodes.TLS_DIRECTORY_TRUNCATED)]
        assert regions == ["tls_callbacks_read_failed",
                           "tls_callbacks_max_exceeded"]


# =================================================================
# 201 — cascade early-return when ImageBase is not an int
# =================================================================

class TestCascadeImageBaseNotInt:
    def test_in_range_pointer_but_no_image_base_returns(self):
        # Valid range, non-zero in-range pointer, but image_base is None ->
        # the pointer cannot be converted to an RVA, so line 201 returns
        # without emitting a mapping issue. callbacks=[] so step 4 is a no-op.
        tls = _tls(start_address_of_raw_data=0x1000,
                   end_address_of_raw_data=0x2000,
                   address_of_callbacks=0x1500,   # in [start, end)
                   image_base=None,
                   callbacks=[])
        issues = _run(tls, analysis={"extended": [],
                                     "sections": [{"virtual_address": 0,
                                                   "virtual_size": 0x9000}]})
        # No pointer-mapping / executability issues emitted; clean early exit.
        assert ReasonCodes.TLS_CALLBACK_NOT_MAPPED_TO_SECTION not in _codes(issues)
        assert ReasonCodes.TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION not in _codes(issues)
        assert issues == []


# =================================================================
# 263 — resolution-tombstone loop body
# =================================================================

class TestResolutionTombstones:
    def test_va_below_image_base_surfaced(self):
        # Parser recorded a resolution tombstone (not a header-decode tag),
        # callbacks=[] -> line 263 loop emits one rva_invalid per tag.
        tls = _tls(errors=["tls_callbacks_va_below_image_base"], callbacks=[])
        issues = _run(tls)
        assert _codes(issues) == [ReasonCodes.TLS_CALLBACK_RVA_INVALID]
        assert _details_for(issues, ReasonCodes.TLS_CALLBACK_RVA_INVALID) == [
            {"reason": "tls_callbacks_va_below_image_base"}]

    def test_both_resolution_tags_sorted_and_deduped(self):
        tls = _tls(errors=["tls_image_base_unavailable",
                           "tls_callbacks_va_below_image_base",
                           "tls_image_base_unavailable"],  # dup
                   callbacks=[])
        issues = _run(tls)
        reasons = [d["reason"] for d in
                   _details_for(issues, ReasonCodes.TLS_CALLBACK_RVA_INVALID)]
        # set() dedupes, sorted() orders deterministically
        assert reasons == ["tls_callbacks_va_below_image_base",
                           "tls_image_base_unavailable"]

    def test_header_decode_tag_does_not_reach_263(self):
        # A header-decode tag short-circuits at step 2; the resolution loop
        # (263) must not run, even though callbacks=[] would otherwise reach it.
        tls = _tls(errors=["tls_directory_truncated"], callbacks=[])
        issues = _run(tls)
        assert _codes(issues) == [ReasonCodes.TLS_DIRECTORY_TRUNCATED]


# =================================================================
# 277-282 — callbacks present but ImageBase not int
# =================================================================

class TestCallbacksPresentNoImageBase:
    def test_image_base_unavailable_with_callbacks(self):
        # callbacks non-empty AND image_base not int -> the 277-282 branch
        # emits a single image_base_unavailable issue and returns.
        tls = _tls(callbacks=[0x401000, 0x402000], image_base=None)
        issues = _run(tls)
        assert _codes(issues).count(ReasonCodes.TLS_CALLBACK_RVA_INVALID) == 1
        assert _details_for(issues, ReasonCodes.TLS_CALLBACK_RVA_INVALID) == [
            {"reason": "image_base_unavailable", "callback_count": 2}]


# =================================================================
# 287 — non-int callback VA is skipped
# =================================================================

class TestNonIntCallbackSkipped:
    def test_non_int_va_continues(self):
        # One non-int VA (skipped at 287) and one valid, mapped VA -> no
        # rva_invalid issue is produced (the non-int is not flagged).
        image_base = 0x400000
        tls = _tls(image_base=image_base,
                   callbacks=["not-an-int", image_base + 0x1500])
        analysis = {"extended": [],
                    "sections": [{"virtual_address": 0x1000,
                                  "virtual_size": 0x1000}]}  # covers rva 0x1500
        issues = _run(tls, analysis=analysis)
        assert ReasonCodes.TLS_CALLBACK_RVA_INVALID not in _codes(issues)


# =================================================================
# 293 — resolved target does not map to any section
# =================================================================

class TestTargetNotMapped:
    def test_unmapped_target_flagged(self):
        image_base = 0x400000
        # rva = 0x8000, but the only section covers [0x1000, 0x1010)
        tls = _tls(image_base=image_base, callbacks=[image_base + 0x8000])
        analysis = {"extended": [],
                    "sections": [{"virtual_address": 0x1000,
                                  "virtual_size": 0x10}]}
        issues = _run(tls, analysis=analysis)
        d = _details_for(issues, ReasonCodes.TLS_CALLBACK_RVA_INVALID)
        assert d == [{"callback_va": image_base + 0x8000,
                      "callback_rva": 0x8000,
                      "reason": "not_mapped",
                      "invalid_callback_count": 1}]

    def test_below_image_base_target_flagged(self):
        # sibling branch: rva < 0 -> below_image_base (kept for contrast)
        image_base = 0x400000
        tls = _tls(image_base=image_base, callbacks=[image_base - 0x10])
        issues = _run(tls, analysis={"extended": [], "sections": []})
        d = _details_for(issues, ReasonCodes.TLS_CALLBACK_RVA_INVALID)
        assert d == [{"callback_va": image_base - 0x10,
                      "reason": "below_image_base",
                      "invalid_callback_count": 1}]
