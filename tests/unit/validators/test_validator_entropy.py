# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.entropy import validate_entropy
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) Continue branch (invalid entropy or raw_size)
# ---------------------------------------------------------

def test_entropy_continue_branch():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": "bad", "raw_size": 2000}, # invalid entropy → continue
            {"name": ".data", "entropy": 5.0, "raw_size": "bad"}, # invalid raw_size → continue
        ]
    }
    issues = validate_entropy({}, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) High entropy section
# ---------------------------------------------------------

def test_entropy_high_section():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": 8.0, "raw_size": 2000},
        ]
    }
    issues = validate_entropy({}, analysis)
    assert ReasonCodes.ENTROPY_HIGH_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 3) Very low entropy section
# ---------------------------------------------------------

def test_entropy_very_low_section():
    analysis = {
        "sections": [
            {"name": ".data", "entropy": 0.1, "raw_size": 20000}, # >= 16 KB
        ]
    }
    issues = validate_entropy({}, analysis)
    assert ReasonCodes.ENTROPY_VERY_LOW_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 4) Overlay high entropy
# ---------------------------------------------------------

def test_entropy_high_overlay():
    analysis = {
        "sections": [],
        "overlay": {"entropy": 8.0, "size": 2000},
    }
    issues = validate_entropy({}, analysis)
    assert ReasonCodes.ENTROPY_HIGH_OVERLAY in make_issue_list(issues)


# ---------------------------------------------------------
# 5) Region-specific entropy (all regions)
# ---------------------------------------------------------

@pytest.mark.parametrize("region,reason", [
    ("resources", ReasonCodes.ENTROPY_HIGH_RESOURCES),
    ("relocations", ReasonCodes.ENTROPY_HIGH_RELOCATIONS),
    ("imports", ReasonCodes.ENTROPY_HIGH_IMPORTS),
    ("tls", ReasonCodes.ENTROPY_HIGH_TLS),
    ("certificate", ReasonCodes.ENTROPY_HIGH_CERTIFICATE),
])
def test_entropy_region_specific(region, reason):
    analysis = {
        "region_entropy": {
            region: {"entropy": 8.0, "size": 2000}
        }
    }
    issues = validate_entropy({}, analysis)
    assert reason in make_issue_list(issues)


# ---------------------------------------------------------
# 6) Uniform entropy across sections
# ---------------------------------------------------------

def test_entropy_uniform_across_sections():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": 7.6, "raw_size": 2000},
            {"name": ".data", "entropy": 7.61, "raw_size": 2000},
            {"name": ".rdata", "entropy": 7.59, "raw_size": 2000},
        ]
    }
    issues = validate_entropy({}, analysis)
    assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in make_issue_list(issues)


# ---------------------------------------------------------
# 7) No issues (baseline)
# ---------------------------------------------------------

def test_entropy_no_issues():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": 5.0, "raw_size": 2000},
            {"name": ".data", "entropy": 4.0, "raw_size": 2000},
        ]
    }
    issues = validate_entropy({}, analysis)
    assert issues == []


# ---------------------------------------------------------
# 8) Mixed: high + low + overlay + region + uniform
# ---------------------------------------------------------

def test_entropy_mixed_all_paths():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": 8.0, "raw_size": 2000}, # high
            {"name": ".data", "entropy": 0.1, "raw_size": 20000}, # very low
            {"name": ".rdata", "entropy": 7.6, "raw_size": 2000}, # normal
        ],
        "overlay": {"entropy": 8.0, "size": 2000},
        "region_entropy": {
            "resources": {"entropy": 8.0, "size": 2000},
        }
    }

    issues = validate_entropy({}, analysis)
    codes = make_issue_list(issues)

    assert ReasonCodes.ENTROPY_HIGH_SECTION in codes
    assert ReasonCodes.ENTROPY_VERY_LOW_SECTION in codes
    assert ReasonCodes.ENTROPY_HIGH_OVERLAY in codes
    assert ReasonCodes.ENTROPY_HIGH_RESOURCES in codes

    # Uniform entropy SHOULD NOT appear here
    assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS not in codes


def test_entropy_uniform_across_sections():
    analysis = {
        "sections": [
            {"name": ".text", "entropy": 7.60, "raw_size": 2000},
            {"name": ".data", "entropy": 7.62, "raw_size": 2000},
            {"name": ".rdata", "entropy": 7.58, "raw_size": 2000},
        ]
    }

    issues = validate_entropy({}, analysis)
    codes = make_issue_list(issues)

    assert ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS in codes
