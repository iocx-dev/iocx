# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_certificates.

Strategy:
- Byte-level fixture builders construct WIN_CERTIFICATE entries directly via
  struct.pack (dwLength + wRevision + wCertificateType + opaque blob).
- Fake PE objects expose OPTIONAL_HEADER.DATA_DIRECTORY[4], __data__ (the
  raw file bytes), and .sections, so the parser's file-offset reads and the
  "outside the image" section-extent computation can be steered directly —
  including __data__ that is absent or refuses bytes(), and sections that
  raise on int().
- Determinism tests assert byte-for-byte stable output across runs.

Note: the security directory's VirtualAddress is a FILE OFFSET, not an RVA,
so all offsets here index into the __data__ buffer.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_certificates import (
    build_certificate_structure,
    _align_up,
    _decode_certificate,
    _image_raw_end,
    _locate_security_directory,
    _raw_file_bytes,
    _read_certificates,
    _CERT_ALIGNMENT,
    _MAX_CERTIFICATES,
    _SECURITY_DIRECTORY_INDEX,
    _WIN_CERT_HEADER_SIZE,
)


# =================================================================
# Byte-level builders
# =================================================================

def _win_cert(revision: int = 0x0200, cert_type: int = 0x0002,
              blob: bytes = b"", dw_length: Optional[int] = None,
              align: bool = True) -> bytes:
    """Build a WIN_CERTIFICATE. dw_length defaults to 8 + len(blob)."""
    if dw_length is None:
        dw_length = _WIN_CERT_HEADER_SIZE + len(blob)
    entry = struct.pack("<IHH", dw_length, revision, cert_type) + blob
    if align:
        pad = (-len(entry)) % _CERT_ALIGNMENT
        entry += b"\x00" * pad
    return entry


# =================================================================
# Fake PE objects
# =================================================================

class _DataDir:
    def __init__(self, va: int, size: int):
        self.VirtualAddress = va
        self.Size = size


class _OptHdr:
    def __init__(self, dd: Optional[_DataDir]):
        self.DATA_DIRECTORY = [None] * 16
        if dd is not None:
            self.DATA_DIRECTORY[_SECURITY_DIRECTORY_INDEX] = dd


class _Section:
    def __init__(self, ptr, raw_size):
        self.PointerToRawData = ptr
        self.SizeOfRawData = raw_size


class _RaisingSection:
    """int(PointerToRawData) raises -> exercises the per-section except path."""
    @property
    def PointerToRawData(self):
        raise ValueError("bad ptr")

    @property
    def SizeOfRawData(self):
        return 0x200


class _FakePE:
    def __init__(self, file_bytes: Optional[bytes] = b"",
                 dd: Optional[_DataDir] = None,
                 sections: Any = (),
                 has_optional_header: bool = True,
                 has_data: bool = True,
                 has_sections: bool = True):
        if has_data:
            self.__data__ = file_bytes
        if has_optional_header:
            self.OPTIONAL_HEADER = _OptHdr(dd)
        if has_sections:
            self.sections = sections


def _pe(file_bytes: bytes, sec_offset: int, sec_size: int,
        sections=()) -> _FakePE:
    """A PE with the security dir at (sec_offset, sec_size) over file_bytes."""
    return _FakePE(file_bytes, _DataDir(sec_offset, sec_size), sections=sections)


# =================================================================
# _locate_security_directory
# =================================================================

class TestLocator:
    def test_valid(self):
        pe = _FakePE(dd=_DataDir(0x800, 0x40))
        assert _locate_security_directory(pe) == (0x800, 0x40)

    def test_zero_offset_none(self):
        assert _locate_security_directory(_FakePE(dd=_DataDir(0, 0x40))) is None

    def test_zero_size_none(self):
        assert _locate_security_directory(_FakePE(dd=_DataDir(0x800, 0))) is None

    def test_missing_optional_header_none(self):
        assert _locate_security_directory(
            _FakePE(has_optional_header=False)) is None

    def test_missing_entry_none(self):
        assert _locate_security_directory(_FakePE()) is None


# =================================================================
# _raw_file_bytes
# =================================================================

class TestRawFileBytes:
    def test_bytes_returned(self):
        assert _raw_file_bytes(_FakePE(b"\x01\x02")) == b"\x01\x02"

    def test_missing_data_none(self):
        assert _raw_file_bytes(_FakePE(has_data=False)) is None

    def test_data_is_none_none(self):
        assert _raw_file_bytes(_FakePE(file_bytes=None)) is None

    def test_bytes_conversion_raises_none(self):
        class _Bad:
            def __bytes__(self):
                raise TypeError("nope")
        pe = _FakePE.__new__(_FakePE)
        pe.__data__ = _Bad()
        assert _raw_file_bytes(pe) is None


# =================================================================
# _image_raw_end
# =================================================================

class TestImageRawEnd:
    def test_no_sections_attr_none(self):
        pe = _FakePE(has_sections=False)
        assert _image_raw_end(pe) is None

    def test_empty_sections_none(self):
        assert _image_raw_end(_FakePE(sections=[])) is None

    def test_max_across_sections(self):
        secs = [_Section(0x200, 0x400), _Section(0x600, 0x200)]  # ends 0x600, 0x800
        assert _image_raw_end(_FakePE(sections=secs)) == 0x800

    def test_raising_section_skipped(self):
        secs = [_RaisingSection(), _Section(0x200, 0x400)]
        assert _image_raw_end(_FakePE(sections=secs)) == 0x600

    def test_zero_fields_skipped(self):
        # ptr==0 or raw_size==0 -> not counted; all-zero -> end stays 0 -> None
        assert _image_raw_end(_FakePE(sections=[_Section(0, 0x400)])) is None
        assert _image_raw_end(_FakePE(sections=[_Section(0x200, 0)])) is None


# =================================================================
# _align_up
# =================================================================

class TestAlignUp:
    def test_already_aligned(self):
        assert _align_up(16, 8) == 16

    def test_rounds_up(self):
        assert _align_up(9, 8) == 16
        assert _align_up(1, 8) == 8

    def test_nonpositive_alignment_returns_value(self):
        assert _align_up(13, 0) == 13
        assert _align_up(13, -4) == 13


# =================================================================
# _decode_certificate
# =================================================================

class TestDecodeCertificate:
    def test_known_revision_and_type(self):
        cert = _decode_certificate(0, 0x100, 0x0200, 0x0002, 0x800, 0x1000, [])
        assert cert["revision_name"] == "REVISION_2_0"
        assert cert["cert_type_name"] == "PKCS_SIGNED_DATA"
        assert cert["data_length"] == 0x100 - 8
        assert cert["errors"] == []

    def test_length_too_small(self):
        cert = _decode_certificate(0, 4, 0x0200, 0x0002, 0x800, 0x1000, [])
        assert cert["errors"] == ["length_too_small"]
        assert cert["data_length"] == 0

    def test_unknown_revision(self):
        cert = _decode_certificate(0, 0x20, 0x0999, 0x0002, 0x800, 0x1000, [])
        assert "unknown_revision" in cert["errors"]

    def test_unknown_cert_type(self):
        cert = _decode_certificate(0, 0x20, 0x0200, 0x00FF, 0x800, 0x1000, [])
        assert "unknown_cert_type" in cert["errors"]

    def test_blob_truncated_clamps_data_length(self):
        trunc: List[str] = []
        # dw_length claims 0x100 payload, but only 0x10 available to dir_end
        cert = _decode_certificate(0, 0x100, 0x0200, 0x0002,
                                   entry_offset=0x800, dir_end=0x818,
                                   truncations=trunc)
        assert "certificate_blob_truncated" in trunc
        assert cert["data_length"] == 0x818 - (0x800 + 8)  # clamped


# =================================================================
# _read_certificates — array walk
# =================================================================

class TestReadCertificates:
    def test_single_certificate(self):
        cert = _win_cert(blob=b"\xAA" * 16)
        data = bytes(0x800) + cert
        trunc: List[str] = []
        errs: List[str] = []
        out = _read_certificates(data, 0x800, len(cert), len(data), trunc, errs)
        assert len(out) == 1
        assert out[0]["length"] == 8 + 16
        assert trunc == [] and errs == []

    def test_multiple_8byte_aligned(self):
        table = _win_cert(blob=b"\xAA" * 20) + _win_cert(blob=b"\xBB" * 12)
        data = bytes(0x800) + table
        out = _read_certificates(data, 0x800, len(table), len(data), [], [])
        assert len(out) == 2

    def test_offset_past_eof(self):
        errs: List[str] = []
        out = _read_certificates(bytes(0x100), 0x800, 0x40, 0x100, [], errs)
        assert out == []
        assert "certificate_offset_past_eof" in errs

    def test_table_truncated_clamps_end(self):
        trunc: List[str] = []
        # declared end (0x800 + 0x400) runs past file_size 0x820
        cert = _win_cert(blob=b"\x00" * 8)
        data = bytes(0x800) + cert
        out = _read_certificates(data, 0x800, 0x400, len(data), trunc, [])
        assert "certificate_table_truncated" in trunc
        assert len(out) == 1

    def test_header_truncated(self):
        trunc: List[str] = []
        # window leaves < 8 bytes for a header (end 4 bytes past base)
        data = bytes(0x800) + b"\x10\x00\x00\x00"  # 4 stray bytes
        out = _read_certificates(data, 0x800, 4, len(data), trunc, [])
        assert out == []
        assert "certificate_header_truncated" in trunc

    def test_length_too_small_stops_walk(self):
        # dwLength = 4 (< 8) -> decoder tags length_too_small; walk stops
        bad = struct.pack("<IHH", 4, 0x0200, 0x0002)
        data = bytes(0x800) + bad + bytes(0x40)
        out = _read_certificates(data, 0x800, 0x40, len(data), [], [])
        assert len(out) == 1
        assert out[0]["errors"] == ["length_too_small"]

    def test_max_certificates_exceeded(self):
        # 1025 minimal (8-byte) certificates -> loop exhausts -> else branch
        one = struct.pack("<IHH", 8, 0x0200, 0x0002)  # dw_length == 8, no blob
        n = _MAX_CERTIFICATES + 1
        table = one * n
        data = bytes(0x800) + table
        trunc: List[str] = []
        out = _read_certificates(data, 0x800, len(table), len(data), trunc, [])
        assert len(out) == _MAX_CERTIFICATES
        assert "certificate_max_exceeded" in trunc

    def test_header_unpack_error_is_defensive(self, monkeypatch):
        # With end <= len(data), unpack_from always has >= 8 bytes, so this
        # handler is unreachable in practice. Force it via monkeypatch to
        # exercise the certificate_header_unpack_failed_* tombstone.
        import iocx.parsers.pe_certificates as M
        orig = M.struct.unpack_from

        def boom(fmt, buf, off=0):
            if fmt == "<IHH":
                raise struct.error("forced")
            return orig(fmt, buf, off)

        monkeypatch.setattr(M.struct, "unpack_from", boom)
        data = bytes(0x800) + _win_cert(blob=b"\x00" * 8)
        errs: List[str] = []
        out = _read_certificates(data, 0x800, 0x18, len(data), [], errs)
        assert out == []
        assert any(e.startswith("certificate_header_unpack_failed")
                   for e in errs)


# =================================================================
# build_certificate_structure — full roundtrips & contract
# =================================================================

class TestBuildCertificateStructure:
    def test_absent_returns_none(self):
        assert build_certificate_structure(_FakePE(dd=None)) is None

    def test_raw_file_unavailable(self):
        # security dir present but __data__ missing -> raw_file_unavailable
        pe = _FakePE(dd=_DataDir(0x800, 0x40), has_data=False)
        out = build_certificate_structure(pe)
        assert out["errors"] == ["raw_file_unavailable"]
        assert out["file_size"] is None
        assert out["overlaps_image"] is None
        assert out["certificates"] == []

    def test_overlaps_image_true(self):
        # cert offset 0x400 before section raw end 0x800 -> overlaps_image True
        cert = _win_cert(blob=b"\x00" * 8)
        data = bytearray(0x1000)
        data[0x400:0x400 + len(cert)] = cert
        pe = _pe(bytes(data), 0x400, len(cert),
                 sections=[_Section(0x200, 0x600)])  # raw end 0x800
        out = build_certificate_structure(pe)
        assert out["overlaps_image"] is True
        assert out["image_raw_end"] == 0x800

    def test_overlaps_image_false(self):
        cert = _win_cert(blob=bytes(range(32)))
        data = bytes(0x800) + cert
        pe = _pe(data, 0x800, len(cert), sections=[_Section(0x200, 0x600)])
        out = build_certificate_structure(pe)
        assert out["overlaps_image"] is False
        assert out["certificate_count"] == 1

    def test_overlaps_image_none_when_no_sections(self):
        # image_raw_end None (no sections) -> overlaps_image evaluates False,
        # but we assert on the underlying image_raw_end being None.
        cert = _win_cert(blob=b"\x00" * 8)
        data = bytes(0x800) + cert
        pe = _pe(data, 0x800, len(cert), sections=[])
        out = build_certificate_structure(pe)
        assert out["image_raw_end"] is None
        assert out["overlaps_image"] is False

    def test_contract_keys(self):
        cert = _win_cert(blob=b"\x00" * 8)
        data = bytes(0x800) + cert
        out = build_certificate_structure(
            _pe(data, 0x800, len(cert), sections=[_Section(0x200, 0x600)]))
        for k in ("offset", "size", "file_size", "image_raw_end",
                  "overlaps_image", "certificates", "certificate_count",
                  "truncations", "errors"):
            assert k in out
        for k in ("index", "offset", "length", "revision", "revision_name",
                  "cert_type", "cert_type_name", "data_length", "errors"):
            assert k in out["certificates"][0]

    def test_json_serializable(self):
        import json
        cert = _win_cert(blob=b"\x00" * 8)
        data = bytes(0x800) + cert
        out = build_certificate_structure(
            _pe(data, 0x800, len(cert), sections=[_Section(0x200, 0x600)]))
        json.dumps(out)  # must not raise


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def _pe(self):
        table = _win_cert(blob=b"\xAA" * 20) + _win_cert(0x0999, 0x00FF, b"\xBB" * 4)
        data = bytes(0x800) + table
        return _pe(data, 0x800, len(table), sections=[_Section(0x200, 0x600)])

    def test_repeated_calls_identical(self):
        import json
        a = build_certificate_structure(self._pe())
        b = build_certificate_structure(self._pe())
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
