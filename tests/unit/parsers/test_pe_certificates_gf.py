# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Gap-filling tests for pe_certificates and validators.signature.

These cover paths the existing suites leave unexercised. Each class states
what a regression would look like, because several of these behaviours are
deliberate and read as bugs without that context.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_certificates import (
    build_certificate_structure, _align_up, _decode_certificate,
    _read_certificates, _CERT_ALIGNMENT, _WIN_CERT_HEADER_SIZE,
    _SECURITY_DIRECTORY_INDEX,
)
from iocx.reason_codes import ReasonCodes
from iocx.validators.signature import validate_signature


# =================================================================
# Builders
# =================================================================

def _header(dw_length: int, revision: int = 0x0200,
            cert_type: int = 0x0002) -> bytes:
    return struct.pack("<IHH", dw_length, revision, cert_type)


def _entry(blob: bytes, revision: int = 0x0200, cert_type: int = 0x0002,
           pad: bool = True) -> bytes:
    """
    A WIN_CERTIFICATE. `pad` appends the inter-entry padding a conformant
    file carries - dwLength counts only the header plus blob, so an entry
    whose dwLength is not a multiple of 8 is followed by padding bytes that
    the walk skips via _align_up.
    """
    entry = _header(_WIN_CERT_HEADER_SIZE + len(blob), revision, cert_type) + blob
    if pad:
        entry += b"\x00" * ((-len(entry)) % _CERT_ALIGNMENT)
    return entry


class _DataDir:
    def __init__(self, va, size):
        self.VirtualAddress = va
        self.Size = size

class _OptHdr:
    def __init__(self, dd):
        self.DATA_DIRECTORY = [None] * 16
        if dd is not None:
            self.DATA_DIRECTORY[_SECURITY_DIRECTORY_INDEX] = dd

class _Section:
    def __init__(self, ptr, raw_size):
        self.PointerToRawData = ptr
        self.SizeOfRawData = raw_size

class _FakePE:
    def __init__(self, file_bytes=b"", dd=None, sections=()):
        self.__data__ = file_bytes
        self.OPTIONAL_HEADER = _OptHdr(dd)
        self.sections = sections


# =================================================================
# PARSER - 8-byte alignment advance
# =================================================================

class TestAlignmentAdvance:
    """
    dwLength counts the header plus blob only; entries are QWORD-aligned, so
    the walk must advance by _align_up(dwLength, 8).

    The existing suite's multi-entry fixture uses blob sizes that are
    already 8-aligned, so removing _align_up entirely would not fail any
    test - the walk would read the next header at the same offset either
    way. These fixtures use dwLength values that are NOT multiples of 8.
    """

    @pytest.mark.parametrize("blob_size,expected_advance", [
        (1, 16),    # dwLength 9
        (5, 16),    # dwLength 13
        (7, 16),    # dwLength 15
        (13, 24),   # dwLength 21
    ])
    def test_second_entry_found_at_aligned_offset(self, blob_size, expected_advance):
        first = _entry(b"\xAA" * blob_size)
        second = _entry(b"\xBB" * 4)
        data = bytes(0x800) + first + second
        out = _read_certificates(data, 0x800, len(first) + len(second),
                                 len(data), [], [])
        assert len(out) == 2
        assert out[1]["offset"] == 0x800 + expected_advance
        assert out[1]["length"] == _WIN_CERT_HEADER_SIZE + 4

    def test_already_aligned_length_advances_unchanged(self):
        """Control: an 8-aligned dwLength must not be padded further."""
        first = _entry(b"\xAA" * 8)      # dwLength 16
        second = _entry(b"\xBB" * 4)
        data = bytes(0x800) + first + second
        out = _read_certificates(data, 0x800, len(first) + len(second),
                                 len(data), [], [])
        assert out[1]["offset"] == 0x800 + 16

    def test_three_unaligned_entries_walk_correctly(self):
        """
        Cumulative alignment: a single mis-advance desynchronises every
        subsequent entry, so a chain catches an off-by-one the pair misses.
        """
        blobs = [b"\xAA" * 5, b"\xBB" * 13, b"\xCC" * 1]
        table = b"".join(_entry(b) for b in blobs)
        data = bytes(0x800) + table
        out = _read_certificates(data, 0x800, len(table), len(data), [], [])
        assert [c["length"] for c in out] == [13, 21, 9]
        assert [c["offset"] for c in out] == [0x800, 0x810, 0x828]


# =================================================================
# PARSER - non-advancing cursor
# =================================================================

class TestNonAdvancingLength:
    """
    A dwLength below the 8-byte header cannot advance the cursor. The walk
    must record the malformed entry and stop; the existing suite tests only
    dwLength == 4.
    """

    @pytest.mark.parametrize("dw_length", [0, 1, 7])
    def test_walk_stops_and_tags(self, dw_length):
        data = bytes(0x800) + _header(dw_length) + bytes(0x40)
        out = _read_certificates(data, 0x800, 0x40, len(data), [], [])
        assert len(out) == 1
        assert out[0]["errors"] == ["length_too_small"]
        assert out[0]["data_length"] == 0

    def test_zero_length_does_not_hang(self):
        """
        dwLength == 0 is the classic infinite-loop shape: advance by zero,
        read the same header forever. The `< header size` break is what
        prevents it.
        """
        data = bytes(0x800) + _header(0) * 4 + bytes(0x40)
        out = _read_certificates(data, 0x800, 0x60, len(data), [], [])
        assert len(out) == 1

    def test_minimum_valid_length_continues(self):
        """Control: dwLength exactly 8 is valid and the walk proceeds."""
        data = bytes(0x800) + _header(8) + _entry(b"\xBB" * 4)
        out = _read_certificates(data, 0x800, 0x20, len(data), [], [])
        assert len(out) == 2
        assert out[0]["errors"] == []


# =================================================================
# PARSER - offset / file-size boundary
# =================================================================

class TestOffsetBoundary:
    """
    The guard is `base_offset > file_size`, not `>=`. An offset exactly at
    EOF is therefore not tagged past-EOF; the walk simply finds nothing.
    """

    def test_offset_past_eof_tagged(self):
        errors: List[str] = []
        out = _read_certificates(bytes(0x100), 0x101, 0x40, 0x100, [], errors)
        assert out == []
        assert errors == ["certificate_offset_past_eof"]

    def test_offset_exactly_at_eof_is_not_tagged(self):
        """
        Boundary: offset == file_size yields an empty walk rather than a
        past-EOF error. Pinned so a change from `>` to `>=` is deliberate.
        """
        errors: List[str] = []
        truncations: List[str] = []
        out = _read_certificates(bytes(0x100), 0x100, 0x40, 0x100,
                                 truncations, errors)
        assert out == []
        assert errors == []
        assert truncations == ["certificate_table_truncated"]


# =================================================================
# PARSER - blob clamp
# =================================================================

class TestBlobTruncationClamp:

    def test_data_length_clamped_to_available(self):
        truncations: List[str] = []
        cert = _decode_certificate(0, 0x100, 0x0200, 0x0002,
                                   entry_offset=0x800, dir_end=0x818,
                                   truncations=truncations)
        assert truncations == ["certificate_blob_truncated"]
        assert cert["data_length"] == 0x818 - (0x800 + _WIN_CERT_HEADER_SIZE)

    def test_negative_available_clamps_to_zero(self):
        """
        When dir_end falls before the end of the header itself, `available`
        is negative and must clamp to 0 rather than producing a negative
        data_length in output.
        """
        truncations: List[str] = []
        cert = _decode_certificate(0, 0x100, 0x0200, 0x0002,
                                   entry_offset=0x800, dir_end=0x804,
                                   truncations=truncations)
        assert cert["data_length"] == 0
        assert truncations == ["certificate_blob_truncated"]


# =================================================================
# PARSER - overlaps_image semantics
# =================================================================

class TestOverlapsImageSemantics:
    """
    overlaps_image is False both when the table genuinely sits after the
    image AND when image_raw_end could not be computed. The validator's
    `is True` test treats them alike, so False means "not known to overlap",
    not "verified outside the image".
    """

    def test_false_when_genuinely_outside(self):
        cert = _entry(b"\x00" * 8)
        pe = _FakePE(bytes(0x800) + cert, _DataDir(0x800, len(cert)),
                     sections=[_Section(0x200, 0x600)])   # raw end 0x800
        out = build_certificate_structure(pe)
        assert out["image_raw_end"] == 0x800
        assert out["overlaps_image"] is False

    def test_false_when_image_raw_end_unknown(self):
        """
        Same value, different meaning: no sections means the invariant could
        not be evaluated. Pinned so the ambiguity is a recorded decision
        rather than an accident.
        """
        cert = _entry(b"\x00" * 8)
        pe = _FakePE(bytes(0x800) + cert, _DataDir(0x800, len(cert)),
                     sections=[])
        out = build_certificate_structure(pe)
        assert out["image_raw_end"] is None
        assert out["overlaps_image"] is False

    def test_true_when_before_image_end(self):
        cert = _entry(b"\x00" * 8)
        data = bytearray(0x1000)
        data[0x400:0x400 + len(cert)] = cert
        pe = _FakePE(bytes(data), _DataDir(0x400, len(cert)),
                     sections=[_Section(0x200, 0x600)])
        out = build_certificate_structure(pe)
        assert out["overlaps_image"] is True


# =================================================================
# VALIDATOR - field value sets
# =================================================================

def _cert(offset=0x800, length=0x40, revision=0x0200, cert_type=0x0002):
    return {"offset": offset, "length": length, "revision": revision,
            "cert_type": cert_type, "errors": []}


def _struct(certs, **kw):
    d = {"offset": 0x800, "size": 0x200, "file_size": None,
         "image_raw_end": None, "overlaps_image": False,
         "certificates": certs, "certificate_count": len(certs),
         "truncations": [], "errors": []}
    d.update(kw)
    return d


def _run(cert_struct, has_signature=True, analysis=None):
    return validate_signature({"certificate_struct": cert_struct},
                              {"has_signature": has_signature},
                              analysis if analysis is not None else {})


def _codes(issues):
    return [i["issue"] for i in issues]


class TestFieldValueSets:
    """
    The parser and validator use DIFFERENT accepted-value sets for
    cert_type, deliberately: the parser NAMES 0x0003/0x0004 (so output shows
    RESERVED_1 / TS_STACK_SIGNED) while the validator REJECTS them, because
    Authenticode uses only X509 and PKCS_SIGNED_DATA in practice.

    A future edit aligning the two sets would silently stop flagging
    reserved types, so both halves are pinned here.
    """

    @pytest.mark.parametrize("revision", [0x0100, 0x0200])
    def test_both_valid_revisions_accepted(self, revision):
        issues = _run(_struct([_cert(revision=revision)]),
                      analysis={"file_size": 0x10000})
        assert ReasonCodes.SIGNATURE_INVALID_REVISION not in _codes(issues)

    @pytest.mark.parametrize("cert_type", [0x0001, 0x0002])
    def test_both_valid_cert_types_accepted(self, cert_type):
        issues = _run(_struct([_cert(cert_type=cert_type)]),
                      analysis={"file_size": 0x10000})
        assert ReasonCodes.SIGNATURE_INVALID_TYPE not in _codes(issues)

    @pytest.mark.parametrize("cert_type", [0x0003, 0x0004])
    def test_parser_named_but_validator_rejected_types(self, cert_type):
        """
        0x0003 and 0x0004 appear in the parser's _CERT_TYPE_NAMES but are
        not accepted by the validator. The divergence is intentional.
        """
        issues = _run(_struct([_cert(cert_type=cert_type)]),
                      analysis={"file_size": 0x10000})
        assert ReasonCodes.SIGNATURE_INVALID_TYPE in _codes(issues)


# =================================================================
# VALIDATOR - suppression and break behaviour
# =================================================================

class TestSuppressionBehaviour:
    """
    Two deliberate narrowings that read as under-reporting. Both are pinned
    so a change is a decision rather than a drift.
    """

    def test_out_of_bounds_suppresses_overlay_and_section_checks(self):
        """
        The bounds check `continue`s, so a certificate that is out of bounds
        AND overlaps both the overlay and a section reports once.
        """
        issues = _run(
            _struct([_cert(offset=900, length=200)]),
            analysis={"file_size": 1000, "overlay_offset": 950,
                      "sections": [{"name": ".text", "raw_address": 900,
                                    "raw_size": 100}]})
        assert _codes(issues) == [ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS]

    def test_section_overlap_reports_only_the_first_section(self):
        """The section loop breaks on the first hit, so a certificate
        spanning several sections names one."""
        issues = _run(
            _struct([_cert(offset=100, length=200)]),
            analysis={"file_size": 1000,
                      "sections": [{"name": ".a", "raw_address": 150, "raw_size": 50},
                                   {"name": ".b", "raw_address": 250, "raw_size": 50}]})
        overlaps = [i["details"]["section"] for i in issues
                    if i["issue"] == ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA]
        assert overlaps == [".a"]

    def test_overlay_and_section_can_both_fire(self):
        """
        Control for the first test: without the bounds failure, the overlay
        and section checks are independent and both report.
        """
        issues = _run(
            _struct([_cert(offset=100, length=200)]),
            analysis={"file_size": 1000, "overlay_offset": 150,
                      "sections": [{"name": ".a", "raw_address": 150,
                                    "raw_size": 50}]})
        assert _codes(issues).count(
            ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA) == 2


class TestOverlayBoundary:
    """`offset < overlay < offset + length` excludes both endpoints."""

    @pytest.mark.parametrize("overlay,fires", [
        (100, False),   # == offset
        (101, True),    # just inside
        (299, True),    # just inside
        (300, False),   # == offset + length
    ])
    def test_endpoints_excluded(self, overlay, fires):
        issues = _run(_struct([_cert(offset=100, length=200)]),
                      analysis={"file_size": 1000, "overlay_offset": overlay})
        assert (ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA in _codes(issues)) is fires


class TestFileSizeFallback:
    """
    file_size prefers the analysis layer and falls back to the parser's
    value. The fallback branch is otherwise unexercised.
    """

    def test_falls_back_to_parser_file_size(self):
        issues = _run(_struct([_cert(offset=900, length=200)], file_size=1000),
                      analysis={})
        assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS in _codes(issues)

    def test_analysis_value_takes_precedence(self):
        """Parser says 1000 (would fail), analysis says 2000 (passes)."""
        issues = _run(_struct([_cert(offset=900, length=200)], file_size=1000),
                      analysis={"file_size": 2000})
        assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS not in _codes(issues)

    def test_no_file_size_anywhere_skips_bounds_check(self):
        issues = _run(_struct([_cert(offset=900, length=200)]), analysis={})
        assert ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS not in _codes(issues)
