# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_imports.

Strategy:
- Byte-level builders construct 20-byte IMAGE_IMPORT_DESCRIPTOR structures,
  NULL-terminated thunk arrays, and IMAGE_IMPORT_BY_NAME blobs via struct.pack.
- A fake PE exposes OPTIONAL_HEADER.Magic / DATA_DIRECTORY[1] and get_data(),
  with a base-RVA lookup so thunk walks (which increment the RVA one element
  at a time) resolve correctly, and a raise_at hook for read failures.

The two divergences from pe_delay_imports carry their own test classes,
because both are cases where a plausible implementation misreports rather
than fails loudly:

  * OriginalFirstThunk == 0 is LEGAL here (delay-load treats a zero INT as
    an anomaly). Getting this wrong flags a large fraction of legitimate
    binaries, so TestOriginalFirstThunkFallback asserts the absence of a tag
    as well as the successful fallback.

  * TimeDateStamp selects how FirstThunk should be read. Only the old-style
    bound case makes the fallback unusable.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_imports import (
    build_import_structure,
    _decode_descriptor,
    _decode_import_entry,
    _is_pe32_plus,
    _is_zero_descriptor,
    _locate_import_directory,
    _read_asciiz,
    _read_import_by_name,
    _read_thunk_array,
    _BOUND_NEW_STYLE,
    _DESCRIPTOR_SIZE,
    _DLL_NAME_MAX_CHARS,
    _IMPORT_DIRECTORY_INDEX,
    _MAGIC_PE32,
    _MAGIC_PE32_PLUS,
    _MAX_IMPORTS_PER_DESCRIPTOR,
)


# =================================================================
# Byte-level builders
# =================================================================

def _descriptor(original_first_thunk: int = 0x3000,
                timestamp: int = 0,
                forwarder_chain: int = 0,
                name_rva: int = 0x2000,
                first_thunk: int = 0x4000) -> bytes:
    """A 20-byte IMAGE_IMPORT_DESCRIPTOR."""
    return struct.pack("<IIIII", original_first_thunk, timestamp,
                       forwarder_chain, name_rva, first_thunk)


def _zero_descriptor() -> bytes:
    return b"\x00" * _DESCRIPTOR_SIZE


def _thunks64(values: List[int]) -> bytes:
    return b"".join(struct.pack("<Q", v) for v in values) + struct.pack("<Q", 0)


def _thunks32(values: List[int]) -> bytes:
    return b"".join(struct.pack("<I", v) for v in values) + struct.pack("<I", 0)


def _import_by_name(hint: int, name: str) -> bytes:
    return struct.pack("<H", hint) + name.encode("ascii") + b"\x00"


def _asciiz(s: str) -> bytes:
    return s.encode("ascii") + b"\x00"


def _ordinal64(o: int) -> int:
    return (1 << 63) | o


def _ordinal32(o: int) -> int:
    return 0x80000000 | o


# =================================================================
# Fake PE
# =================================================================

class _DataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _OptHdr:
    def __init__(self, d: Optional[_DataDir], magic: int = _MAGIC_PE32_PLUS,
                 has_magic: bool = True):
        self.DATA_DIRECTORY = [None] * 16
        if d is not None:
            self.DATA_DIRECTORY[_IMPORT_DIRECTORY_INDEX] = d
        if has_magic:
            self.Magic = magic


class _FakePE:
    """
    get_data resolves an RVA against the nearest preceding buffer base, so a
    thunk walk stepping 8 bytes at a time reads successive elements of one
    stored array. A read past a buffer's end returns a short slice (as pefile
    does at a section edge); an unmapped RVA raises.
    """
    def __init__(self, import_rva: int = 0, import_size: int = 0,
                 data: Optional[Dict[int, bytes]] = None,
                 is_64bit: bool = True,
                 raise_at: Optional[int] = None,
                 has_optional_header: bool = True,
                 has_magic: bool = True):
        magic = _MAGIC_PE32_PLUS if is_64bit else _MAGIC_PE32
        if has_optional_header:
            dd = _DataDir(import_rva, import_size) if (import_rva or import_size) else None
            self.OPTIONAL_HEADER = _OptHdr(dd, magic, has_magic)
        self._data = data or {}
        self._raise_at = raise_at

    def get_data(self, rva: int, size: int) -> bytes:
        if self._raise_at is not None and rva == self._raise_at:
            raise RuntimeError("simulated read failure")
        for base in sorted((b for b in self._data if b <= rva), reverse=True):
            buf = self._data[base]
            offset = rva - base
            if offset <= len(buf):
                return buf[offset:offset + size]
        raise ValueError(f"no fixture data covers rva {rva:#x}")


def _pe(descriptors: bytes, extra: Optional[Dict[int, bytes]] = None,
        size: Optional[int] = None, is_64bit: bool = True,
        raise_at: Optional[int] = None) -> _FakePE:
    data = {0x1000: descriptors}
    data.update(extra or {})
    return _FakePE(0x1000, size if size is not None else len(descriptors),
                   data, is_64bit=is_64bit, raise_at=raise_at)


def _simple(**kw) -> _FakePE:
    """One well-formed descriptor: KERNEL32.dll, one named + one ordinal."""
    return _pe(_descriptor(**kw) + _zero_descriptor(), {
        0x2000: _asciiz("KERNEL32.dll"),
        0x3000: _thunks64([0x5000, _ordinal64(42)]),
        0x4000: _thunks64([0x5000, _ordinal64(42)]),
        0x5000: _import_by_name(0x10, "LoadLibraryA"),
    }, size=60)


# =================================================================
# Absence / locator
# =================================================================

class TestLocator:

    def test_absent_directory_returns_none(self):
        assert build_import_structure(_FakePE(0, 0)) is None

    def test_zero_rva_returns_none(self):
        assert _locate_import_directory(_FakePE(0, 100)) is None

    def test_zero_size_returns_none(self):
        assert _locate_import_directory(_FakePE(0x1000, 0)) is None

    def test_missing_optional_header_returns_none(self):
        assert _locate_import_directory(
            _FakePE(has_optional_header=False)) is None

    def test_missing_entry_returns_none(self):
        pe = _FakePE(0x1000, 100)
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMPORT_DIRECTORY_INDEX] = None
        assert _locate_import_directory(pe) is None

    def test_non_int_fields_return_none(self):
        pe = _FakePE(0x1000, 100)
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            _IMPORT_DIRECTORY_INDEX].VirtualAddress = "nope"
        assert _locate_import_directory(pe) is None


class TestPe32Plus:

    def test_pe32_plus_true(self):
        assert _is_pe32_plus(_FakePE(is_64bit=True)) is True

    def test_pe32_false(self):
        assert _is_pe32_plus(_FakePE(is_64bit=False)) is False

    def test_missing_magic_defaults_false(self):
        """Conservative default: narrower thunks, lower over-read risk."""
        assert _is_pe32_plus(_FakePE(has_magic=False)) is False

    def test_missing_optional_header_defaults_false(self):
        assert _is_pe32_plus(_FakePE(has_optional_header=False)) is False


# =================================================================
# Descriptor decode
# =================================================================

class TestDescriptorDecode:

    def test_fields_decoded(self):
        raw = _descriptor(original_first_thunk=0x1111, timestamp=0x2222,
                          forwarder_chain=0x3333, name_rva=0x4444,
                          first_thunk=0x5555)
        d = _decode_descriptor(raw, 7)
        assert d["index"] == 7
        assert d["original_first_thunk"] == 0x1111
        assert d["timestamp"] == 0x2222
        assert d["forwarder_chain"] == 0x3333
        assert d["name_rva"] == 0x4444
        assert d["first_thunk"] == 0x5555

    def test_zero_descriptor_recognised(self):
        assert _is_zero_descriptor(_decode_descriptor(_zero_descriptor(), 0)) is True

    def test_non_zero_descriptor_not_terminator(self):
        assert _is_zero_descriptor(_decode_descriptor(_descriptor(), 0)) is False

    def test_terminator_is_not_emitted_as_an_entry(self):
        out = build_import_structure(_simple())
        assert out["descriptor_count"] == 1

    def test_multiple_descriptors_walked_in_order(self):
        table = (_descriptor(original_first_thunk=0x3000, name_rva=0x2000)
                 + _descriptor(original_first_thunk=0, first_thunk=0x4000,
                               name_rva=0x2010)
                 + _zero_descriptor())
        out = build_import_structure(_pe(table, {
            0x2000: _asciiz("A.dll"), 0x2010: _asciiz("B.dll"),
            0x3000: _thunks64([0x5000]), 0x4000: _thunks64([_ordinal64(9)]),
            0x5000: _import_by_name(1, "Fn"),
        }, size=80))
        assert [d["index"] for d in out["descriptors"]] == [0, 1]
        assert [d["dll_name"] for d in out["descriptors"]] == ["A.dll", "B.dll"]


# =================================================================
# DIVERGENCE 1 - OriginalFirstThunk == 0 is legal
# =================================================================

class TestOriginalFirstThunkFallback:
    """
    Unlike the delay-load INT, a zero OriginalFirstThunk is legal and common:
    older linkers emit only FirstThunk, which then holds INT-style thunks on
    disk. Treating it as an anomaly would misreport a large fraction of
    legitimate binaries, so the absence of an error tag is asserted as
    explicitly as the successful fallback.
    """

    def test_fallback_resolves_names_from_first_thunk(self):
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0, first_thunk=0x4000)
            + _zero_descriptor(), {
                0x2000: _asciiz("OLD.dll"),
                0x4000: _thunks64([0x5000]),
                0x5000: _import_by_name(1, "Foo"),
            }, size=60))
        d = out["descriptors"][0]
        assert d["thunk_source"] == "iat_fallback"
        assert [e["name"] for e in d["imports"]] == ["Foo"]

    def test_fallback_is_not_flagged_as_an_error(self):
        """The regression guard: a zero INT must NOT produce a tag."""
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0, first_thunk=0x4000)
            + _zero_descriptor(), {
                0x2000: _asciiz("OLD.dll"),
                0x4000: _thunks64([_ordinal64(1)]),
            }, size=60))
        assert out["descriptors"][0]["errors"] == []

    def test_int_preferred_when_both_present(self):
        """
        With both arrays populated the INT wins - it is the on-disk name
        source, and the IAT may already hold bound addresses.
        """
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0x3000, first_thunk=0x4000)
            + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([0x5000]),
                0x4000: _thunks64([0x6000]),
                0x5000: _import_by_name(1, "FromINT"),
                0x6000: _import_by_name(2, "FromIAT"),
            }, size=60))
        d = out["descriptors"][0]
        assert d["thunk_source"] == "int"
        assert d["imports"][0]["name"] == "FromINT"

    def test_neither_array_present_is_flagged(self):
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0, first_thunk=0)
            + _zero_descriptor(), {0x2000: _asciiz("X.dll")}, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == ["no_thunk_array"]
        assert d["thunk_source"] is None
        assert d["imports"] == []

    def test_truncation_tag_names_the_array_actually_read(self):
        """
        The tag prefix follows thunk_source, so a consumer can tell whether
        the INT or the fallback IAT was short.
        """
        int_short = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(),
            {0x2000: _asciiz("A.dll"), 0x3000: b"\x01\x02\x03"}, size=60))
        fallback_short = build_import_structure(_pe(
            _descriptor(original_first_thunk=0) + _zero_descriptor(),
            {0x2000: _asciiz("A.dll"), 0x4000: b"\x01\x02\x03"}, size=60))
        assert int_short["truncations"] == ["int_truncated"]
        assert fallback_short["truncations"] == ["iat_fallback_truncated"]


# =================================================================
# DIVERGENCE 2 - TimeDateStamp selects how FirstThunk reads
# =================================================================

class TestBoundState:

    @pytest.mark.parametrize("timestamp,expected", [
        (0, "unbound"),
        (_BOUND_NEW_STYLE, "bound_new_style"),
        (0x5F000000, "bound_old_style"),
        (1, "bound_old_style"),
    ])
    def test_bound_state_classification(self, timestamp, expected):
        out = build_import_structure(_pe(
            _descriptor(timestamp=timestamp) + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([_ordinal64(1)]),
            }, size=60))
        assert out["descriptors"][0]["bound_state"] == expected

    def test_old_style_bound_without_int_cannot_recover_names(self):
        """
        Old-style bound means FirstThunk holds resolved ADDRESSES on disk.
        With no INT there is no name source at all - a structural fact, not a
        parse failure, so no thunks are walked.
        """
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0, timestamp=0x5F000000,
                        first_thunk=0x4000) + _zero_descriptor(), {
                0x2000: _asciiz("BOUND.dll"),
                0x4000: _thunks64([0x7FF800001234]),
            }, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == ["names_unrecoverable_bound_no_int"]
        assert d["thunk_source"] is None
        assert d["imports"] == []

    def test_old_style_bound_with_int_still_parses(self):
        """The INT is unaffected by binding, so names remain readable."""
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0x3000, timestamp=0x5F000000)
            + _zero_descriptor(), {
                0x2000: _asciiz("B.dll"),
                0x3000: _thunks64([0x5000]),
                0x5000: _import_by_name(1, "Bar"),
            }, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == []
        assert d["imports"][0]["name"] == "Bar"

    def test_new_style_bound_without_int_uses_the_fallback(self):
        """
        New-style bound keeps real timestamps in the BOUND_IMPORT directory,
        so FirstThunk still holds thunks on disk and the fallback is valid.
        """
        out = build_import_structure(_pe(
            _descriptor(original_first_thunk=0, timestamp=_BOUND_NEW_STYLE,
                        first_thunk=0x4000) + _zero_descriptor(), {
                0x2000: _asciiz("NB.dll"),
                0x4000: _thunks64([0x5000]),
                0x5000: _import_by_name(1, "Baz"),
            }, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == []
        assert d["thunk_source"] == "iat_fallback"
        assert d["imports"][0]["name"] == "Baz"


# =================================================================
# Thunk decode
# =================================================================

class TestThunkDecode:

    def test_named_import(self):
        d = build_import_structure(_simple())["descriptors"][0]
        e = d["imports"][0]
        assert e["is_ordinal"] is False
        assert e["hint"] == 0x10
        assert e["name"] == "LoadLibraryA"
        assert e["name_rva"] == 0x5000
        assert e["name_valid"] is True
        assert e["errors"] == []

    def test_ordinal_import(self):
        e = build_import_structure(_simple())["descriptors"][0]["imports"][1]
        assert e["is_ordinal"] is True
        assert e["ordinal"] == 42
        assert e["name"] is None

    def test_ordinal_masked_to_low_16_bits(self):
        """Per spec the ordinal is bits 15-0; higher bits are discarded."""
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([_ordinal64(42) | (1 << 40)]),
            }, size=60))
        assert out["descriptors"][0]["imports"][0]["ordinal"] == 42

    def test_ordinal_zero_flagged(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([_ordinal64(0)]),
            }, size=60))
        assert out["descriptors"][0]["imports"][0]["errors"] == ["ordinal_zero"]

    def test_pe32_uses_dword_thunks(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("K32.dll"),
                0x3000: _thunks32([0x5000, _ordinal32(7)]),
                0x5000: _import_by_name(2, "Baz"),
            }, size=60, is_64bit=False))
        assert out["is_64bit"] is False
        entries = out["descriptors"][0]["imports"]
        assert entries[0]["name"] == "Baz"
        assert entries[1]["ordinal"] == 7

    @pytest.mark.parametrize("blob,tag", [
        (b"\x42",                                  "name_too_short"),
        (struct.pack("<H", 1) + b"A" * 2000,       "name_unterminated"),
        (struct.pack("<H", 1) + b"a\xffb\x00",     "name_non_ascii"),
    ])
    def test_import_by_name_failures(self, blob, tag):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([0x5000]),
                0x5000: blob,
            }, size=60))
        assert tag in out["descriptors"][0]["imports"][0]["errors"]

    def test_empty_import_name_flagged(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([0x5000]),
                0x5000: struct.pack("<H", 1) + b"\x00",
            }, size=60))
        e = out["descriptors"][0]["imports"][0]
        assert e["errors"] == ["name_empty"]
        assert e["name_valid"] is False

    def test_long_printable_name_is_valid(self):
        """
        Mangled C++ symbols legitimately exceed any small cap; only the
        1024-byte read bounds the name, and printability is the only check.
        """
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"),
                0x3000: _thunks64([0x5000]),
                0x5000: _import_by_name(1, "A" * 600),
            }, size=60))
        e = out["descriptors"][0]["imports"][0]
        assert e["name_valid"] is True
        assert e["errors"] == []


# =================================================================
# DLL name
# =================================================================

class TestDllName:

    def test_valid_name(self):
        d = build_import_structure(_simple())["descriptors"][0]
        assert d["dll_name"] == "KERNEL32.dll"
        assert d["dll_name_valid"] is True

    @pytest.mark.parametrize("blob,tag", [
        (b"\x00",                    "dll_name_empty"),
        (b"kernel\x0132.dll\x00",    "dll_name_not_printable"),
        (b"D" * 300 + b"\x00",       "dll_name_too_long"),
    ])
    def test_three_way_split(self, blob, tag):
        """
        Empty, non-printable and over-long are distinct faults: a consumer
        triaging on "not_printable" should not be shown a length violation.
        """
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: blob, 0x3000: _thunks64([_ordinal64(1)]),
            }, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == [tag]
        assert d["dll_name_valid"] is False

    def test_name_at_the_length_limit_is_valid(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("D" * _DLL_NAME_MAX_CHARS),
                0x3000: _thunks64([_ordinal64(1)]),
            }, size=60))
        assert out["descriptors"][0]["dll_name_valid"] is True

    def test_zero_name_rva_flagged(self):
        out = build_import_structure(_pe(
            _descriptor(name_rva=0) + _zero_descriptor(),
            {0x3000: _thunks64([_ordinal64(1)])}, size=60))
        assert out["descriptors"][0]["errors"] == ["dll_name_rva_zero"]

    def test_name_failure_does_not_stop_the_thunk_walk(self):
        """Both facts are recorded; a bad name does not hide the imports."""
        out = build_import_structure(_pe(
            _descriptor(name_rva=0) + _zero_descriptor(),
            {0x3000: _thunks64([_ordinal64(5)])}, size=60))
        d = out["descriptors"][0]
        assert d["errors"] == ["dll_name_rva_zero"]
        assert len(d["imports"]) == 1

    def test_read_failure_tagged(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(),
            {0x3000: _thunks64([_ordinal64(1)])}, size=60, raise_at=0x2000))
        assert out["descriptors"][0]["errors"] == ["read_failed"]


# =================================================================
# Truncation / limits
# =================================================================

class TestTruncations:

    def test_descriptor_read_failure(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), size=60, raise_at=0x1000))
        assert out["truncations"] == ["import_descriptor_read_failed"]
        assert out["descriptors"] == []

    def test_short_descriptor_read(self):
        pe = _FakePE(0x1000, 60, {0x1000: b"\x01" * 12})
        out = build_import_structure(pe)
        assert out["truncations"] == ["import_descriptor_truncated"]

    def test_unterminated_when_declared_size_ends_the_array(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(), {
                0x2000: _asciiz("A.dll"), 0x3000: _thunks64([_ordinal64(1)]),
            }, size=_DESCRIPTOR_SIZE))
        assert out["truncations"] == ["import_descriptor_unterminated"]
        assert out["descriptor_count"] == 1

    def test_no_unterminated_tag_when_nothing_decoded(self):
        """
        A window too small for even one descriptor is not an 'unterminated
        array' - there was no array. Guards against tagging an empty walk.
        """
        out = build_import_structure(_pe(_descriptor(), size=10))
        assert out["truncations"] == []
        assert out["descriptors"] == []

    def test_properly_terminated_array_is_clean(self):
        out = build_import_structure(_simple())
        assert out["truncations"] == []
        assert out["errors"] == []

    def test_thunk_read_failure(self):
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(),
            {0x2000: _asciiz("A.dll")}, size=60, raise_at=0x3000))
        assert out["truncations"] == ["int_read_failed"]

    def test_imports_per_descriptor_cap(self):
        blob = b"".join(struct.pack("<Q", _ordinal64((i % 0xFFFE) + 1))
                        for i in range(_MAX_IMPORTS_PER_DESCRIPTOR + 50))
        out = build_import_structure(_pe(
            _descriptor() + _zero_descriptor(),
            {0x2000: _asciiz("A.dll"), 0x3000: blob}, size=60))
        assert len(out["descriptors"][0]["imports"]) == _MAX_IMPORTS_PER_DESCRIPTOR
        assert "int_max_exceeded" in out["truncations"]


# =================================================================
# Helpers
# =================================================================

class TestReadAsciiz:

    @pytest.mark.parametrize("rva,blob,expected", [
        (0,      None,                     (None, "rva_zero")),
        (0x2000, b"",                      (None, "empty_read")),
        (0x2000, b"A" * 600,               (None, "unterminated")),
        (0x2000, b"kernel32.dll\x00",      ("kernel32.dll", None)),
    ])
    def test_outcomes(self, rva, blob, expected):
        pe = _FakePE(0x1000, 60, {0x2000: blob} if blob is not None else {})
        assert _read_asciiz(pe, rva, 512) == expected

    def test_read_failure(self):
        pe = _FakePE(0x1000, 60, {}, raise_at=0x2000)
        assert _read_asciiz(pe, 0x2000, 512) == (None, "read_failed")

    def test_non_ascii_returns_replacement_and_tag(self):
        pe = _FakePE(0x1000, 60, {0x2000: b"caf\xc3\xa9\x00"})
        s, err = _read_asciiz(pe, 0x2000, 512)
        assert err == "non_ascii"
        assert s is not None


class TestReadImportByName:

    def test_valid(self):
        pe = _FakePE(0x1000, 60, {0x6000: _import_by_name(0x42, "FooFunc")})
        assert _read_import_by_name(pe, 0x6000) == (0x42, "FooFunc", None)

    def test_zero_rva(self):
        assert _read_import_by_name(_FakePE(), 0) == (None, None, "name_rva_zero")

    def test_read_failure(self):
        pe = _FakePE(0x1000, 60, {}, raise_at=0x6000)
        assert _read_import_by_name(pe, 0x6000) == (None, None, "name_read_failed")

    def test_too_short(self):
        pe = _FakePE(0x1000, 60, {0x6000: b"\x42"})
        assert _read_import_by_name(pe, 0x6000)[2] == "name_too_short"

    def test_unterminated_preserves_hint(self):
        pe = _FakePE(0x1000, 60, {0x6000: struct.pack("<H", 0x42) + b"A" * 2000})
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert (hint, name, err) == (0x42, None, "name_unterminated")


class TestReadThunkArray:

    def test_walks_to_null_terminator(self):
        pe = _FakePE(0x1000, 60, {0x3000: _thunks64([0x11, 0x22, 0x33])})
        assert _read_thunk_array(pe, 0x3000, 8, "int", [], []) == [0x11, 0x22, 0x33]

    def test_empty_array_returns_empty(self):
        pe = _FakePE(0x1000, 60, {0x3000: struct.pack("<Q", 0)})
        assert _read_thunk_array(pe, 0x3000, 8, "int", [], []) == []

    def test_short_read_tagged(self):
        trunc: List[str] = []
        pe = _FakePE(0x1000, 60, {0x3000: b"\x01\x02\x03"})
        assert _read_thunk_array(pe, 0x3000, 8, "int", [], trunc) == []
        assert trunc == ["int_truncated"]


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_top_level_keys(self):
        out = build_import_structure(_simple())
        assert set(out) == {"rva", "size", "is_64bit", "descriptors",
                            "descriptor_count", "truncations", "errors"}

    def test_descriptor_keys(self):
        d = build_import_structure(_simple())["descriptors"][0]
        assert set(d) == {"index", "original_first_thunk", "timestamp",
                          "forwarder_chain", "name_rva", "first_thunk",
                          "bound_state", "dll_name", "dll_name_valid",
                          "thunk_source", "imports", "errors"}

    def test_import_entry_keys(self):
        e = build_import_structure(_simple())["descriptors"][0]["imports"][0]
        assert set(e) == {"index", "thunk_value", "is_ordinal", "ordinal",
                          "hint", "name", "name_rva", "name_valid", "errors"}

    def test_descriptor_count_matches_list(self):
        out = build_import_structure(_simple())
        assert out["descriptor_count"] == len(out["descriptors"])

    def test_json_serialisable(self):
        import json
        json.dumps(build_import_structure(_simple()))

    def test_never_raises_on_random_bytes(self):
        import os
        for _ in range(200):
            blob = os.urandom(120)
            pe = _FakePE(0x1000, 60, {k: blob for k in
                                      (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)})
            assert isinstance(build_import_structure(pe), dict)


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_parse_identical(self):
        import json
        first = json.dumps(build_import_structure(_simple()), sort_keys=True)
        for _ in range(20):
            assert json.dumps(build_import_structure(_simple()),
                              sort_keys=True) == first

    def test_malformed_input_deterministic(self):
        import json
        def build():
            return build_import_structure(_pe(
                _descriptor(original_first_thunk=0, timestamp=0x5F000000)
                + _descriptor(name_rva=0, original_first_thunk=0x3000)
                + _zero_descriptor(), {
                    0x2000: b"bad\x01\x00",
                    0x3000: _thunks64([_ordinal64(0), 0x5000]),
                    0x4000: _thunks64([0x9999]),
                    0x5000: struct.pack("<H", 1) + b"A" * 2000,
                }, size=80))
        first = json.dumps(build(), sort_keys=True)
        for _ in range(20):
            assert json.dumps(build(), sort_keys=True) == first
