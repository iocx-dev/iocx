# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.signature.validate_signature.

v0.7.6 migration: the validator now takes THREE positional arguments
(internal, metadata, analysis) via @depends_on("internal","metadata",
"analysis"), and sources per-certificate structural truth from
internal["certificate_struct"] (produced by parser pe_certificates),
NOT from the old pefile-derived metadata["signatures"] list.

Per-certificate field names follow the parser's CertificateStruct:
    offset, length, revision, cert_type   (was: file_offset, length,
                                            revision, certificate_type)

Only metadata["has_signature"] and the analysis geometry
(file_size / overlay_offset / sections) are still read from those dicts.
"""

import pytest

from iocx.validators.signature import validate_signature
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def make_issue_list(result):
    return [i["issue"] for i in result]


def _cert_struct(certificates, *, errors=None, truncations=None,
                 overlaps_image=False, offset=0x800, size=0x200,
                 file_size=None, image_raw_end=None):
    """Build an internal['certificate_struct'] as parser pe_certificates emits."""
    return {
        "offset": offset, "size": size, "file_size": file_size,
        "image_raw_end": image_raw_end, "overlaps_image": overlaps_image,
        "certificates": certificates, "certificate_count": len(certificates),
        "truncations": truncations or [], "errors": errors or [],
    }


def _internal(cert_struct):
    return {"certificate_struct": cert_struct}


# ---------------------------------------------------------
# 1) Flag/metadata symmetry
# ---------------------------------------------------------

def test_flag_set_but_no_metadata():
    # has_signature True, but no certificates decoded
    internal = _internal(_cert_struct([]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert make_issue_list(issues) == [
        ReasonCodes.SIGNATURE_FLAG_SET_BUT_NO_METADATA
    ]


def test_signature_present_but_flag_not_set():
    internal = _internal(_cert_struct(
        [{"offset": 0, "length": 16, "revision": 0x0200, "cert_type": 0x0002,
          "errors": []}]))
    metadata = {"has_signature": False}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_PRESENT_BUT_FLAG_NOT_SET in make_issue_list(issues)


def test_no_sigs_and_flag_false_returns_clean():
    internal = _internal(_cert_struct([]))
    metadata = {"has_signature": False}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) Multiplicity
# ---------------------------------------------------------

def test_multiple_signatures_detected():
    internal = _internal(_cert_struct([
        {"offset": 0, "length": 16, "revision": 0x0200, "cert_type": 0x0002, "errors": []},
        {"offset": 100, "length": 16, "revision": 0x0200, "cert_type": 0x0002, "errors": []},
    ]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_MULTIPLE_CERTIFICATES in make_issue_list(issues)


# ---------------------------------------------------------
# 3) Certificate sanity checks
# ---------------------------------------------------------

def test_invalid_length():
    internal = _internal(_cert_struct([{"offset": 0, "length": 4, "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_LENGTH in make_issue_list(issues)


def test_invalid_revision():
    internal = _internal(_cert_struct(
        [{"offset": 0, "length": 16, "revision": 0x9999, "cert_type": 0x0002,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_REVISION in make_issue_list(issues)


def test_invalid_type():
    internal = _internal(_cert_struct(
        [{"offset": 0, "length": 16, "revision": 0x0200, "cert_type": 0x9999,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_TYPE in make_issue_list(issues)


# ---------------------------------------------------------
# 4) Bounds checks
# ---------------------------------------------------------

def test_signature_out_of_bounds():
    internal = _internal(_cert_struct(
        [{"offset": 900, "length": 200, "revision": 0x0200, "cert_type": 0x0002,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {"file_size": 1000}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS in make_issue_list(issues)


def test_signature_overlaps_overlay():
    internal = _internal(_cert_struct(
        [{"offset": 100, "length": 200, "revision": 0x0200, "cert_type": 0x0002,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {"overlay_offset": 150}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA in make_issue_list(issues)


def test_signature_overlaps_section():
    internal = _internal(_cert_struct(
        [{"offset": 100, "length": 200, "revision": 0x0200, "cert_type": 0x0002,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {"sections": [{"name": ".text", "raw_address": 150, "raw_size": 50}]}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA in make_issue_list(issues)


# ---------------------------------------------------------
# 5) Clean case
# ---------------------------------------------------------

def test_valid_signature_no_issues():
    internal = _internal(_cert_struct(
        [{"offset": 100, "length": 64, "revision": 0x0200, "cert_type": 0x0001,
          "errors": []}]))
    metadata = {"has_signature": True}
    analysis = {"file_size": 1000, "overlay_offset": 2000, "sections": []}
    issues = validate_signature(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 6) Malformed case
# ---------------------------------------------------------

def test_malformed_signature_metadata_skips_entry():
    internal = _internal(_cert_struct(
        [{"offset": "not-an-int", "length": 16, "errors": []}]))  # triggers continue
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    # non-int offset -> entry skipped, no per-cert issue raised
    assert ReasonCodes.SIGNATURE_INVALID_LENGTH not in make_issue_list(issues)
    assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS not in make_issue_list(issues)


# ---------------------------------------------------------
# 7) NEW v0.7.6 codes
# ---------------------------------------------------------

def test_certificate_offset_inside_image():
    internal = _internal(_cert_struct(
        [{"offset": 0x400, "length": 16, "revision": 0x0200, "cert_type": 0x0002,
          "errors": []}],
        overlaps_image=True, offset=0x400, image_raw_end=0x800))
    metadata = {"has_signature": True}
    analysis = {"file_size": 0x1000}
    issues = validate_signature(internal, metadata, analysis)
    assert ReasonCodes.CERTIFICATE_OFFSET_INSIDE_IMAGE in make_issue_list(issues)


def test_certificate_table_malformed_top_level():
    internal = _internal(_cert_struct([], errors=["raw_file_unavailable"]))
    metadata = {"has_signature": True}
    analysis = {}
    issues = validate_signature(internal, metadata, analysis)
    # decode failure short-circuits and is reported as malformed (NOT as
    # flag_set_but_no_metadata)
    assert make_issue_list(issues) == [ReasonCodes.CERTIFICATE_TABLE_MALFORMED]


def test_absent_directory_returns_clean():
    metadata = {"has_signature": False}
    analysis = {}
    assert validate_signature({"certificate_struct": None}, metadata, analysis) == []
    assert validate_signature({}, metadata, analysis) == []
