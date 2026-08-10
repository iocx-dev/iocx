# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_debug.

Strategy:
- Byte-level fixture builders construct 28-byte IMAGE_DEBUG_DIRECTORY
  entries and CodeView (RSDS / NB10) records directly via struct.pack.
- Fake PE objects expose OPTIONAL_HEADER.DATA_DIRECTORY[6], get_data(),
  and __data__, so the parser's RVA reads (get_data) and file-offset reads
  (__data__) can be steered independently — including short reads and
  raising reads that a flat-image stub cannot produce.
- Determinism tests assert byte-for-byte stable output across runs.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_debug import (
    build_debug_structure,
    _decode_entry,
    _extract_asciiz_path,
    _format_guid,
    _locate_debug_directory,
    _read_codeview_blob,
    _read_entries,
    _DEBUG_DIRECTORY_INDEX,
    _DEBUG_ENTRY_SIZE,
    _MAX_DEBUG_ENTRIES,
    _PDB_PATH_MAX_LEN,
)

_GUID16 = bytes(range(16))  # 000102...0f


# =================================================================
# Byte-level builders
# =================================================================

def _entry(dtype: int = 4, size_of_data: int = 0, addr_raw: int = 0,
           ptr_raw: int = 0, characteristics: int = 0, timestamp: int = 0,
           major: int = 0, minor: int = 0) -> bytes:
    """Build one 28-byte IMAGE_DEBUG_DIRECTORY."""
    return struct.pack("<IIHHIIII", characteristics, timestamp, major, minor,
                       dtype, size_of_data, addr_raw, ptr_raw)


def _rsds(pdb: str = "app.pdb", guid: bytes = _GUID16, age: int = 7,
          terminator: bool = True) -> bytes:
    body = b"RSDS" + guid + struct.pack("<I", age) + pdb.encode("ascii")
    return body + (b"\x00" if terminator else b"")


def _nb10(pdb: str = "legacy.pdb", age: int = 3) -> bytes:
    return b"NB10" + struct.pack("<III", 0, 0, age) + pdb.encode("ascii") + b"\x00"


# =================================================================
# Fake PE objects
# =================================================================

class _DataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _OptHdr:
    def __init__(self, dir_dd: Optional[_DataDir]):
        self.DATA_DIRECTORY = [None] * 16
        if dir_dd is not None:
            self.DATA_DIRECTORY[_DEBUG_DIRECTORY_INDEX] = dir_dd


class _FakePE:
    """
    Flat-image pe: RVA == offset into `image`; __data__ is the same buffer
    unless `file` overrides it. get_data clamps and raises only on rva>len.
    """
    def __init__(self, image: bytes = b"",
                 dir_dd: Optional[_DataDir] = None,
                 file: Optional[bytes] = None,
                 has_optional_header: bool = True,
                 has_data: bool = True):
        self._img = bytearray(image)
        if has_data:
            self.__data__ = bytes(file if file is not None else image)
        if has_optional_header:
            self.OPTIONAL_HEADER = _OptHdr(dir_dd)

    def get_data(self, rva: int, size: int) -> bytes:
        if rva < 0 or rva > len(self._img):
            raise ValueError("unmapped RVA")
        return bytes(self._img[rva:rva + size])


class _EntryReadRaisePE:
    """get_data always raises — to drive debug_entry_read_failed."""
    def __init__(self, dir_dd: _DataDir):
        self.OPTIONAL_HEADER = _OptHdr(dir_dd)
        self.__data__ = b""

    def get_data(self, rva, size):
        raise ValueError("boom")


def _pe_one_entry(entry_bytes: bytes, base_rva: int = 0x1000,
                  blob: bytes = b"", blob_at: int = 0x2000,
                  image_size: int = 0x8000,
                  as_file_offset: bool = False) -> _FakePE:
    """
    Place one directory entry at base_rva; optionally place a CodeView blob.
    If as_file_offset, the blob is written only into the __data__ file buffer
    at blob_at (exercising the PointerToRawData path); otherwise into the
    image (RVA path).
    """
    image = bytearray(image_size)
    image[base_rva:base_rva + len(entry_bytes)] = entry_bytes
    file_buf = None
    if blob:
        if as_file_offset:
            file_buf = bytearray(image_size)
            file_buf[blob_at:blob_at + len(blob)] = blob
        else:
            image[blob_at:blob_at + len(blob)] = blob
    return _FakePE(bytes(image), _DataDir(base_rva, len(entry_bytes)),
                   file=bytes(file_buf) if file_buf is not None else None)


# =================================================================
# _locate_debug_directory
# =================================================================

class TestLocator:
    def test_valid(self):
        pe = _FakePE(dir_dd=_DataDir(0x1000, 0x1C))
        assert _locate_debug_directory(pe) == (0x1000, 0x1C)

    def test_zero_rva_none(self):
        assert _locate_debug_directory(_FakePE(dir_dd=_DataDir(0, 0x1C))) is None

    def test_zero_size_none(self):
        assert _locate_debug_directory(_FakePE(dir_dd=_DataDir(0x1000, 0))) is None

    def test_missing_optional_header_none(self):
        assert _locate_debug_directory(_FakePE(has_optional_header=False)) is None

    def test_missing_entry_none(self):
        assert _locate_debug_directory(_FakePE()) is None


# =================================================================
# _read_entries — array-level truncation paths
# =================================================================

class TestReadEntries:
    def test_size_not_entry_aligned(self):
        trunc: List[str] = []
        errs: List[str] = []
        # declared size not a multiple of 28, but < one entry so loop no-ops
        _read_entries(_FakePE(bytes(0x100)), 0x0, 10, trunc, errs)
        assert "debug_directory_size_not_entry_aligned" in trunc

    def test_entry_count_exceeds_max(self):
        trunc: List[str] = []
        big = (_MAX_DEBUG_ENTRIES + 5) * _DEBUG_ENTRY_SIZE
        image = bytearray((_MAX_DEBUG_ENTRIES + 5) * _DEBUG_ENTRY_SIZE + 0x10)
        pe = _FakePE(bytes(image))
        _read_entries(pe, 0x0, big, trunc, [])
        assert "debug_directory_entry_count_exceeds_max" in trunc

    def test_entry_read_failed(self):
        trunc: List[str] = []
        pe = _EntryReadRaisePE(_DataDir(0x1000, _DEBUG_ENTRY_SIZE))
        _read_entries(pe, 0x1000, _DEBUG_ENTRY_SIZE, trunc, [])
        assert "debug_entry_read_failed" in trunc

    def test_entry_truncated_short_read(self):
        trunc: List[str] = []
        # image holds only 12 of the 28 entry bytes
        image = bytearray(0x1000 + 12)
        pe = _FakePE(bytes(image), _DataDir(0x1000, _DEBUG_ENTRY_SIZE))
        _read_entries(pe, 0x1000, _DEBUG_ENTRY_SIZE, trunc, [])
        assert "debug_entry_truncated" in trunc


# =================================================================
# _decode_entry — header + non-CodeView
# =================================================================

class TestDecodeEntry:
    def test_fields_decoded(self):
        raw = _entry(dtype=4, size_of_data=0x40, addr_raw=0x3000,
                     ptr_raw=0x900, timestamp=0x600D, major=1, minor=2)
        e = _decode_entry(_FakePE(), 0, raw)
        assert e["type"] == 4 and e["type_name"] == "MISC"
        assert e["size_of_data"] == 0x40
        assert e["address_of_raw_data"] == 0x3000
        assert e["pointer_to_raw_data"] == 0x900
        assert e["timestamp"] == 0x600D
        assert e["major_version"] == 1 and e["minor_version"] == 2
        assert e["errors"] == []
        # non-CodeView entries are not enriched
        assert e["cv_signature"] is None and e["pdb_path"] is None

    def test_unknown_type_name_none(self):
        e = _decode_entry(_FakePE(), 0, _entry(dtype=99))
        assert e["type"] == 99 and e["type_name"] is None

    def test_unpack_failure_tombstone(self):
        # fewer than 28 bytes -> struct.error -> entry_unpack_failed
        e = _decode_entry(_FakePE(), 5, b"\x00" * 10)
        assert e == {"index": 5, "errors": ["entry_unpack_failed"]}


# =================================================================
# CodeView enrichment — RSDS / NB10 / opaque
# =================================================================

class TestCodeViewRSDS:
    def test_rsds_via_file_pointer(self):
        blob = _rsds(pdb=r"C:\src\app.pdb", age=7)
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, blob_at=0x2000, as_file_offset=True)
        out = build_debug_structure(pe)
        e = out["entries"][0]
        assert e["cv_signature"] == "RSDS"
        assert e["pdb_path"] == r"C:\src\app.pdb"
        assert e["age"] == 7
        assert e["guid"] == "03020100-0504-0706-0809-0A0B0C0D0E0F"
        assert e["errors"] == []

    def test_rsds_via_rva_fallback(self):
        # ptr_raw = 0 forces the AddressOfRawData (RVA) branch
        blob = _rsds(pdb="rva.pdb")
        raw = _entry(dtype=2, size_of_data=len(blob), addr_raw=0x2000, ptr_raw=0)
        pe = _pe_one_entry(raw, blob=blob, blob_at=0x2000, as_file_offset=False)
        e = build_debug_structure(pe)["entries"][0]
        assert e["cv_signature"] == "RSDS" and e["pdb_path"] == "rva.pdb"

    def test_rsds_truncated(self):
        # RSDS signature but < 24 bytes total
        blob = b"RSDS" + b"\x00" * 10
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_rsds_truncated" in e["errors"]

    def test_rsds_unterminated_pdb_path(self):
        blob = _rsds(pdb="A" * 40, terminator=False)
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "pdb_path_unterminated" in e["errors"]
        assert e["pdb_path"] == "A" * 40  # took what it had

    def test_rsds_non_ascii_pdb_path(self):
        body = b"RSDS" + _GUID16 + struct.pack("<I", 1) + b"a\xffb\x00"
        raw = _entry(dtype=2, size_of_data=len(body), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=body, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "pdb_path_non_ascii" in e["errors"]
        assert e["pdb_path"] is not None  # replacement-decoded

    def test_rsds_empty_pdb_path_returns_none(self):
        body = b"RSDS" + _GUID16 + struct.pack("<I", 1) + b"\x00"
        raw = _entry(dtype=2, size_of_data=len(body), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=body, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert e["pdb_path"] is None
        assert e["errors"] == []


class TestCodeViewNB10:
    def test_nb10_ok(self):
        blob = _nb10(pdb="legacy.pdb", age=3)
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert e["cv_signature"] == "NB10"
        assert e["pdb_path"] == "legacy.pdb" and e["age"] == 3
        assert e["guid"] is None  # NB10 carries no GUID

    def test_nb10_truncated(self):
        blob = b"NB10" + b"\x00" * 6  # < 16
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_nb10_truncated" in e["errors"]


class TestCodeViewOther:
    def test_unknown_signature(self):
        blob = b"XXYY" + bytes(range(20))
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_signature_unknown" in e["errors"]

    def test_codeview_too_short(self):
        blob = b"RS"  # < 4 bytes
        raw = _entry(dtype=2, size_of_data=len(blob), ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_too_short" in e["errors"]

    def test_codeview_read_failed_no_pointers(self):
        # CodeView entry but both ptr_raw and addr_raw are zero -> blob None
        raw = _entry(dtype=2, size_of_data=0x20, addr_raw=0, ptr_raw=0)
        pe = _pe_one_entry(raw)  # no blob placed
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_read_failed" in e["errors"]

    def test_codeview_rva_read_raises(self):
        # ptr_raw=0 so RVA branch taken; addr_raw beyond image -> get_data raises
        raw = _entry(dtype=2, size_of_data=0x20, addr_raw=0x99999, ptr_raw=0)
        image = bytearray(0x2000)
        image[0x1000:0x1000 + len(raw)] = raw
        pe = _FakePE(bytes(image), _DataDir(0x1000, len(raw)))
        e = build_debug_structure(pe)["entries"][0]
        assert "codeview_read_failed" in e["errors"]

    def test_size_of_data_zero_uses_max_len(self):
        # size_of_data == 0 -> read_len falls back to _CODEVIEW_MAX_LEN,
        # and a valid RSDS blob is still decoded.
        blob = _rsds(pdb="zero.pdb")
        raw = _entry(dtype=2, size_of_data=0, ptr_raw=0x2000)
        pe = _pe_one_entry(raw, blob=blob, as_file_offset=True)
        e = build_debug_structure(pe)["entries"][0]
        assert e["pdb_path"] == "zero.pdb"


# =================================================================
# _read_codeview_blob — direct unit coverage of fallbacks
# =================================================================

class TestReadCodeViewBlob:
    def test_no_data_attr_falls_through_to_rva(self):
        # __data__ absent -> file-pointer branch skipped; RVA branch used
        image = bytearray(0x3000)
        image[0x2000:0x2004] = b"RSDS"
        pe = _FakePE(bytes(image), has_data=False)
        entry = {"pointer_to_raw_data": 0x900, "address_of_raw_data": 0x2000}
        blob = _read_codeview_blob(pe, entry, 16)
        assert blob[:4] == b"RSDS"

    def test_both_pointers_zero_returns_none(self):
        pe = _FakePE(bytes(0x100))
        entry = {"pointer_to_raw_data": 0, "address_of_raw_data": 0}
        assert _read_codeview_blob(pe, entry, 16) is None

    def test_data_bytes_conversion_raises_falls_through_to_rva(self):
        # __data__ present but bytes(__data__) raises TypeError -> the
        # except (TypeError, ValueError): pass branch runs, then the RVA
        # fallback (address_of_raw_data) is used instead.
        class _BadData:
            def __bytes__(self):
                raise TypeError("cannot convert")

        image = bytearray(0x3000)
        image[0x2000:0x2004] = b"RSDS"
        pe = _FakePE(bytes(image))          # normal image for get_data
        pe.__data__ = _BadData()            # but __data__ refuses bytes()
        entry = {"pointer_to_raw_data": 0x900, "address_of_raw_data": 0x2000}
        blob = _read_codeview_blob(pe, entry, 16)
        assert blob[:4] == b"RSDS"          # RVA fallback succeeded


# =================================================================
# _extract_asciiz_path — direct edge cases
# =================================================================

class TestExtractAsciizPath:
    def test_terminated(self):
        e = {"errors": []}
        assert _extract_asciiz_path(b"abc\x00xxxx", 0, e) == "abc"
        assert e["errors"] == []

    def test_unterminated_within_cap(self):
        e = {"errors": []}
        region = b"Z" * (_PDB_PATH_MAX_LEN + 10)  # no NUL
        out = _extract_asciiz_path(region, 0, e)
        assert "pdb_path_unterminated" in e["errors"]
        assert out == "Z" * _PDB_PATH_MAX_LEN  # capped

    def test_empty_returns_none(self):
        e = {"errors": []}
        assert _extract_asciiz_path(b"\x00rest", 0, e) is None


# =================================================================
# _format_guid
# =================================================================

class TestFormatGuid:
    def test_canonical_mixed_endian(self):
        assert _format_guid(_GUID16) == "03020100-0504-0706-0809-0A0B0C0D0E0F"

    def test_short_returns_none(self):
        assert _format_guid(b"\x00" * 8) is None


# =================================================================
# build_debug_structure — full roundtrips & contract
# =================================================================

class TestBuildDebugStructure:
    def test_absent_returns_none(self):
        assert build_debug_structure(_FakePE()) is None

    def test_multiple_entries(self):
        cv = _rsds(pdb="multi.pdb")
        e0 = _entry(dtype=2, size_of_data=len(cv), ptr_raw=0x2000)
        e1 = _entry(dtype=13, size_of_data=0x40, addr_raw=0x3000)  # POGO opaque
        table = e0 + e1
        image = bytearray(0x8000)
        image[0x1000:0x1000 + len(table)] = table
        file_buf = bytearray(0x8000)
        file_buf[0x2000:0x2000 + len(cv)] = cv
        pe = _FakePE(bytes(image), _DataDir(0x1000, len(table)),
                     file=bytes(file_buf))
        out = build_debug_structure(pe)
        assert out["entry_count"] == 2
        assert out["entries"][0]["type_name"] == "CODEVIEW"
        assert out["entries"][1]["type_name"] == "POGO"

    def test_contract_keys(self):
        raw = _entry(dtype=4)
        out = build_debug_structure(_pe_one_entry(raw))
        for k in ("rva", "size", "entries", "entry_count",
                  "truncations", "errors"):
            assert k in out
        entry = out["entries"][0]
        for k in ("index", "characteristics", "timestamp", "major_version",
                  "minor_version", "type", "type_name", "size_of_data",
                  "address_of_raw_data", "pointer_to_raw_data", "pdb_path",
                  "cv_signature", "guid", "age", "errors"):
            assert k in entry

    def test_json_serializable(self):
        import json
        raw = _entry(dtype=2, size_of_data=len(_rsds()), ptr_raw=0x2000)
        out = build_debug_structure(_pe_one_entry(raw, blob=_rsds(),
                                                  as_file_offset=True))
        json.dumps(out)  # must not raise


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def test_repeated_calls_identical(self):
        import json
        raw = _entry(dtype=2, size_of_data=len(_rsds()), ptr_raw=0x2000)
        a = build_debug_structure(_pe_one_entry(raw, blob=_rsds(), as_file_offset=True))
        b = build_debug_structure(_pe_one_entry(raw, blob=_rsds(), as_file_offset=True))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
