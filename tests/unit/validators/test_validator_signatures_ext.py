# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Targeted tests for the table-truncation block in validate_signature (1a):

    for tag in cert_struct.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.CERTIFICATE_TABLE_MALFORMED,
            details={"reason": "truncation", "region": tag}))

Reaching this block requires a certificate_struct that:
  - has an EMPTY top-level `errors` list (a non-empty one short-circuits at
    step 0 with reason "top_level_decode" and returns before 1a), and
  - has one or more parser `truncations` tags.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.signature import validate_signature


def _cert_struct(certificates=None, *, truncations=None, errors=None,
                 overlaps_image=False, offset=0x800, size=0x200,
                 file_size=0x1000, image_raw_end=None) -> Dict[str, Any]:
    certs = certificates or []
    return {
        "offset": offset, "size": size, "file_size": file_size,
        "image_raw_end": image_raw_end, "overlaps_image": overlaps_image,
        "certificates": certs, "certificate_count": len(certs),
        "truncations": truncations or [], "errors": errors or [],
    }


def _run(cert_struct: Optional[Dict[str, Any]],
         has_signature: bool = True,
         analysis: Optional[Dict[str, Any]] = None):
    return validate_signature(
        {"certificate_struct": cert_struct},
        {"has_signature": has_signature},
        analysis if analysis is not None else {},
    )


def _codes(issues) -> List:
    return [i["issue"] for i in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


class TestTableTruncation:
    def test_single_truncation_tag_emits_malformed(self):
        # one valid cert so the symmetry check passes to reach block 1a
        cert = {"offset": 0x800, "length": 0x40, "revision": 0x0200,
                "cert_type": 0x0002, "errors": []}
        cs = _cert_struct([cert], truncations=["certificate_blob_truncated"])
        issues = _run(cs, analysis={"file_size": 0x1000})
        assert ReasonCodes.CERTIFICATE_TABLE_MALFORMED in _codes(issues)
        details = _details_for(issues, ReasonCodes.CERTIFICATE_TABLE_MALFORMED)
        assert details == [{"reason": "truncation",
                            "region": "certificate_blob_truncated"}]

    def test_truncation_with_no_certificates(self):
        # truncations present, empty errors, no certs. has_signature=False so
        # the present/flag symmetry does not short-circuit before block 1a.
        cs = _cert_struct([], truncations=["certificate_table_truncated"])
        issues = _run(cs, has_signature=False)
        assert _codes(issues) == [ReasonCodes.CERTIFICATE_TABLE_MALFORMED]
        assert _details_for(issues, ReasonCodes.CERTIFICATE_TABLE_MALFORMED) == [
            {"reason": "truncation", "region": "certificate_table_truncated"}]

    def test_multiple_truncation_tags_one_issue_each_in_order(self):
        cs = _cert_struct(
            [], truncations=["certificate_table_truncated",
                             "certificate_header_truncated",
                             "certificate_blob_truncated"])
        issues = _run(cs, has_signature=False)
        malformed = _details_for(issues, ReasonCodes.CERTIFICATE_TABLE_MALFORMED)
        assert [d["region"] for d in malformed] == [
            "certificate_table_truncated",
            "certificate_header_truncated",
            "certificate_blob_truncated"]
        assert all(d["reason"] == "truncation" for d in malformed)

    def test_no_truncations_does_not_emit_malformed(self):
        cs = _cert_struct([], truncations=[])
        issues = _run(cs, has_signature=False)
        assert ReasonCodes.CERTIFICATE_TABLE_MALFORMED not in _codes(issues)

    def test_top_level_error_short_circuits_before_1a(self):
        # A non-empty top-level `errors` must be reported as top_level_decode
        # and MUST NOT also emit a truncation-region issue from block 1a.
        cs = _cert_struct(
            [], errors=["raw_file_unavailable"],
            truncations=["certificate_blob_truncated"])
        issues = _run(cs)
        assert _codes(issues) == [ReasonCodes.CERTIFICATE_TABLE_MALFORMED]
        # single issue, and it is the decode variant (not the truncation one)
        assert _details_for(issues, ReasonCodes.CERTIFICATE_TABLE_MALFORMED) == [
            {"reason": "top_level_decode", "errors": ["raw_file_unavailable"]}]
