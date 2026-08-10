# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.tls.validate_tls.

v0.7.6 migration: the validator now takes THREE positional arguments
(internal, metadata, analysis) via @depends_on("internal","metadata",
"analysis"), and sources TLS structural truth from internal["tls_struct"]
(produced by parser pe_tls), NOT from the old pefile-derived
analysis["extended"] marker.

Key shape changes vs the pre-migration tests:
  * Address fields are VAs on the struct:
        start_address_of_raw_data / end_address_of_raw_data
        address_of_callbacks (the callback-array POINTER)
        image_base           (used to convert VA -> RVA for section mapping)
        callbacks            (LIST of resolved callback target VAs)
  * The old single-int "callbacks" (a pointer) maps to address_of_callbacks.
  * Section mapping is done in RVA space: rva = va - image_base. Tests below
    use image_base = 0 so the VA and RVA spaces coincide, keeping the
    original section/offset numbers intact.
  * The multiplicity check still reads analysis["extended"].
"""

import pytest

from iocx.validators.tls import validate_tls
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


def _tls_struct(*, start, end, address_of_callbacks, callbacks=None,
                image_base=0, errors=None, truncations=None):
    """Build an internal['tls_struct'] as parser pe_tls emits."""
    return {
        "rva": 0x1000, "size": 24, "is_64bit": False, "image_base": image_base,
        "start_address_of_raw_data": start,
        "end_address_of_raw_data": end,
        "address_of_index": 0,
        "address_of_callbacks": address_of_callbacks,
        "size_of_zero_fill": 0, "characteristics": 0,
        "raw_data_size": (None if (isinstance(start, int) and isinstance(end, int)
                                   and end < start)
                          else (end - start if isinstance(start, int)
                                and isinstance(end, int) else None)),
        "callbacks": callbacks or [],
        "callback_count": len(callbacks or []),
        "truncations": truncations or [], "errors": errors or [],
    }


def _internal(tls_struct):
    return {"tls_struct": tls_struct}


# ---------------------------------------------------------
# 1) No TLS entries
# ---------------------------------------------------------

def test_no_tls_entries_returns_clean():
    internal = {}  # no tls_struct
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 2) Multiple TLS directories  (still from analysis["extended"])
# ---------------------------------------------------------

def test_multiple_tls_directories():
    internal = {}  # struct absent; multiplicity is an extended-marker check
    metadata = {}
    analysis = {"extended": [
        {"value": "tls_directory", "metadata": {}},
        {"value": "tls_directory", "metadata": {}},
    ]}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_MULTIPLE_DIRECTORIES in make_issue_list(issues)


# ---------------------------------------------------------
# 3) Malformed TLS metadata (early return on non-int fields)
# ---------------------------------------------------------

def test_malformed_tls_metadata_skips_validation():
    internal = _internal(_tls_struct(
        start="bad", end=200, address_of_callbacks=150))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 4) Invalid range (start > end)  /  zero-length
# ---------------------------------------------------------

def test_tls_invalid_range():
    internal = _internal(_tls_struct(
        start=300, end=200, address_of_callbacks=250))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_INVALID_RANGE in make_issue_list(issues)


def test_tls_zero_length_directory():
    # start == end AND no resolved callbacks -> flagged (narrowed in v0.7.6)
    internal = _internal(_tls_struct(
        start=200, end=200, address_of_callbacks=200, callbacks=[]))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_ZERO_LENGTH_DIRECTORY in make_issue_list(issues)


# ---------------------------------------------------------
# 5) Missing callbacks
# ---------------------------------------------------------

def test_tls_callbacks_missing():
    internal = _internal(_tls_struct(
        start=100, end=200, address_of_callbacks=0))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACKS_MISSING in make_issue_list(issues)


# ---------------------------------------------------------
# 6) Callback pointer outside TLS range
# ---------------------------------------------------------

def test_tls_callback_outside_range():
    internal = _internal(_tls_struct(
        start=100, end=200, address_of_callbacks=500))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_OUTSIDE_RANGE in make_issue_list(issues)


# ---------------------------------------------------------
# 7) Callback pointer not mapped to any section
# ---------------------------------------------------------

def test_tls_callback_not_mapped_to_section():
    internal = _internal(_tls_struct(
        start=100, end=200, address_of_callbacks=150, image_base=0))
    metadata = {}
    analysis = {"extended": [], "sections": []}  # no mapping possible
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_NOT_MAPPED_TO_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 8) Callback mapped to non-executable section
# ---------------------------------------------------------

def test_tls_callback_in_non_executable_section():
    internal = _internal(_tls_struct(
        start=100, end=200, address_of_callbacks=150, image_base=0))
    metadata = {}
    analysis = {
        "extended": [],
        "sections": [{"name": ".data", "virtual_address": 100,
                      "virtual_size": 100, "characteristics": 0x0}],
    }
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION in make_issue_list(issues)


# ---------------------------------------------------------
# 9) Callback inside headers
# ---------------------------------------------------------

def test_tls_callback_in_headers():
    internal = _internal(_tls_struct(
        start=100, end=400, address_of_callbacks=150, image_base=0))
    metadata = {"optional_header": {"size_of_headers": 300}}
    analysis = {
        "extended": [],
        "sections": [{"name": ".text", "virtual_address": 100,
                      "virtual_size": 300, "characteristics": 0x20000000}],
    }
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 10) Callback inside overlay
# ---------------------------------------------------------

def test_tls_callback_in_overlay():
    internal = _internal(_tls_struct(
        start=100, end=400, address_of_callbacks=150, image_base=0))
    metadata = {}
    analysis = {
        "extended": [],
        "overlay_offset": 120,  # overlay starts inside section
        "sections": [{"name": ".text", "virtual_address": 100,
                      "virtual_size": 300, "raw_address": 100,
                      "raw_size": 300, "characteristics": 0x20000000}],
    }
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_IN_OVERLAY in make_issue_list(issues)


# ---------------------------------------------------------
# 11) Clean case
# ---------------------------------------------------------

def test_tls_valid_no_issues():
    internal = _internal(_tls_struct(
        start=100, end=400, address_of_callbacks=150, image_base=0))
    metadata = {"optional_header": {"size_of_headers": 50}}
    analysis = {
        "extended": [],
        "sections": [{"name": ".text", "virtual_address": 100,
                      "virtual_size": 300, "raw_address": 100,
                      "raw_size": 300, "characteristics": 0x20000000}],
        "overlay_offset": 999999,
    }
    issues = validate_tls(internal, metadata, analysis)
    assert issues == []


# ---------------------------------------------------------
# 12) NEW v0.7.6 codes
# ---------------------------------------------------------

def test_tls_directory_truncated_header():
    internal = _internal(_tls_struct(
        start=None, end=None, address_of_callbacks=None,
        errors=["tls_directory_truncated"]))
    metadata = {}
    analysis = {"extended": []}
    issues = validate_tls(internal, metadata, analysis)
    assert make_issue_list(issues) == [ReasonCodes.TLS_DIRECTORY_TRUNCATED]


def test_tls_callback_rva_invalid_target():
    # resolved callback target below image base -> rva_invalid
    internal = _internal(_tls_struct(
        start=0x2000, end=0x2100, address_of_callbacks=0x2050,
        callbacks=[0x100], image_base=0x400000))
    metadata = {}
    analysis = {"extended": [], "sections": []}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_CALLBACK_RVA_INVALID in make_issue_list(issues)


def test_tls_zero_length_with_callbacks_not_flagged():
    # zero-length raw data BUT valid callbacks -> no false positive
    internal = _internal(_tls_struct(
        start=0x1000, end=0x1000, address_of_callbacks=0x1500,
        callbacks=[0x1200], image_base=0))
    metadata = {}
    analysis = {"extended": [], "sections": [
        {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x1000,
         "characteristics": 0x20000000}]}
    issues = validate_tls(internal, metadata, analysis)
    assert ReasonCodes.TLS_ZERO_LENGTH_DIRECTORY not in make_issue_list(issues)
    assert ReasonCodes.TLS_CALLBACK_RVA_INVALID not in make_issue_list(issues)
