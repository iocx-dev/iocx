# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.signature import validate_signature
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) Flag/metadata symmetry
# ---------------------------------------------------------

def test_flag_set_but_no_metadata():
    metadata = {"has_signature": True, "signatures": []}
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert make_issue_list(issues) == [
        ReasonCodes.SIGNATURE_FLAG_SET_BUT_NO_METADATA
    ]


def test_signature_present_but_flag_not_set():
    metadata = {"has_signature": False, "signatures": [{"file_offset": 0, "length": 16}]}
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_PRESENT_BUT_FLAG_NOT_SET in make_issue_list(issues)


def test_no_sigs_and_flag_false_returns_clean():
    metadata = {"has_signature": False, "signatures": []}
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) Multiplicity
# ---------------------------------------------------------

def test_multiple_signatures_detected():
    metadata = {
        "has_signature": True,
        "signatures": [
            {"file_offset": 0, "length": 16},
            {"file_offset": 100, "length": 16},
        ],
    }
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_MULTIPLE_CERTIFICATES in make_issue_list(issues)


# ---------------------------------------------------------
# 3) Certificate sanity checks
# ---------------------------------------------------------

def test_invalid_length():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 0, "length": 4}],
    }
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_LENGTH in make_issue_list(issues)


def test_invalid_revision():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 0, "length": 16, "revision": 0x9999}],
    }
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_REVISION in make_issue_list(issues)


def test_invalid_type():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 0, "length": 16, "certificate_type": 0x9999}],
    }
    analysis = {}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_INVALID_TYPE in make_issue_list(issues)


# ---------------------------------------------------------
# 4) Bounds checks
# ---------------------------------------------------------

def test_signature_out_of_bounds():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 900, "length": 200}],
    }
    analysis = {"file_size": 1000}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS in make_issue_list(issues)


def test_signature_overlaps_overlay():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 100, "length": 200}],
    }
    analysis = {"overlay_offset": 150}
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA in make_issue_list(issues)


def test_signature_overlaps_section():
    metadata = {
        "has_signature": True,
        "signatures": [{"file_offset": 100, "length": 200}],
    }
    analysis = {
        "sections": [
            {"name": ".text", "raw_address": 150, "raw_size": 50}
        ]
    }
    issues = validate_signature(metadata, analysis)
    assert ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA in make_issue_list(issues)


# ---------------------------------------------------------
# 5) Clean case
# ---------------------------------------------------------

def test_valid_signature_no_issues():
    metadata = {
        "has_signature": True,
        "signatures": [{
            "file_offset": 100,
            "length": 64,
            "revision": 0x0200,
            "certificate_type": 0x0001,
        }],
    }
    analysis = {
        "file_size": 1000,
        "overlay_offset": 2000,
        "sections": [],
    }
    issues = validate_signature(metadata, analysis)
    assert issues == []

# ---------------------------------------------------------
# 6) Malformed case
# ---------------------------------------------------------

def test_malformed_signature_metadata_skips_entry():
    metadata = {
        "has_signature": True,
        "signatures": [
            {"file_offset": "not-an-int", "length": 16}, # triggers continue
        ],
    }

    analysis = {
        "file_size": 500,
        "sections": [],
        "overlay_offset": None,
    }

    issues = validate_signature(metadata, analysis)

    # The malformed entry should be skipped entirely — no issues from it.
    assert issues == []
