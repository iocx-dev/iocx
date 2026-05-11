# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.tls import validate_tls
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) No TLS entries
# ---------------------------------------------------------

def test_no_tls_entries_returns_clean():
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) Multiple TLS directories
# ---------------------------------------------------------

def test_multiple_tls_directories():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {}},
            {"value": "tls_directory", "metadata": {}},
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_MULTIPLE_DIRECTORIES in make_issue_list(issues)


# ---------------------------------------------------------
# 3) Malformed TLS metadata (early return)
# ---------------------------------------------------------

def test_malformed_tls_metadata_skips_validation():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": "bad",
                "end_address": 200,
                "callbacks": 150,
            }}
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 4) Invalid range (start >= end)
# ---------------------------------------------------------

def test_tls_invalid_range():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 300,
                "end_address": 200,
                "callbacks": 250,
            }}
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_INVALID_RANGE in make_issue_list(issues)


def test_tls_zero_length_directory():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 200,
                "end_address": 200,
                "callbacks": 200,
            }}
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_ZERO_LENGTH_DIRECTORY in make_issue_list(issues)


# ---------------------------------------------------------
# 5) Missing callbacks
# ---------------------------------------------------------

def test_tls_callbacks_missing():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 200,
                "callbacks": 0,
            }}
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACKS_MISSING in make_issue_list(issues)


# ---------------------------------------------------------
# 6) Callback outside TLS range
# ---------------------------------------------------------

def test_tls_callback_outside_range():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 200,
                "callbacks": 500,
            }}
        ]
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_OUTSIDE_RANGE in make_issue_list(issues)


# ---------------------------------------------------------
# 7) Callback not mapped to any section
# ---------------------------------------------------------

def test_tls_callback_not_mapped_to_section():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 200,
                "callbacks": 150,
            }}
        ],
        "sections": [], # no mapping possible
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_NOT_MAPPED_TO_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 8) Callback mapped to non-executable section
# ---------------------------------------------------------

def test_tls_callback_in_non_executable_section():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 200,
                "callbacks": 150,
            }}
        ],
        "sections": [
            {
                "name": ".data",
                "virtual_address": 100,
                "virtual_size": 100,
                "characteristics": 0x0, # NOT executable
            }
        ],
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 9) Callback inside headers
# ---------------------------------------------------------

def test_tls_callback_in_headers():
    metadata = {
        "optional_header": {"size_of_headers": 300}
    }
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 400,
                "callbacks": 150,
            }}
        ],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 300,
                "characteristics": 0x20000000, # executable
            }
        ],
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 10) Callback inside overlay
# ---------------------------------------------------------

def test_tls_callback_in_overlay():
    metadata = {}
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 400,
                "callbacks": 150,
            }}
        ],
        "overlay_offset": 120, # overlay starts inside section
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 300,
                "raw_address": 100,
                "raw_size": 300,
                "characteristics": 0x20000000,
            }
        ],
    }
    issues = validate_tls(metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_OVERLAY in make_issue_list(issues)


# ---------------------------------------------------------
# 11) Clean case
# ---------------------------------------------------------

def test_tls_valid_no_issues():
    metadata = {
        "optional_header": {"size_of_headers": 50}
    }
    analysis = {
        "extended": [
            {"value": "tls_directory", "metadata": {
                "start_address": 100,
                "end_address": 400,
                "callbacks": 150,
            }}
        ],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 100,
                "virtual_size": 300,
                "raw_address": 100,
                "raw_size": 300,
                "characteristics": 0x20000000, # executable
            }
        ],
        "overlay_offset": 999999,
    }
    issues = validate_tls(metadata, analysis)
    assert issues == []
