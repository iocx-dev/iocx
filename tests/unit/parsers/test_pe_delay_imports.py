# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_delay_imports.

Strategy:
- Byte-level fixture builders construct IMAGE_DELAY_IMPORT_DESCRIPTOR
  structures, INT/IAT thunk arrays, and IMAGE_IMPORT_BY_NAME blobs
  directly via struct.pack.
- Fake PE objects with controlled OPTIONAL_HEADER, DATA_DIRECTORY[13],
  and get_data() responses isolate parser logic from pefile.
- Determinism tests assert byte-for-byte stable output across runs.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_delay_imports import (
    build_delay_import_structure,
    _decode_descriptor,
    _decode_import_entry,
    _is_pe32_plus,
    _is_zero_descriptor,
    _locate_delay_import_directory,
    _read_asciiz,
    _read_import_by_name,
    _read_thunk_array,
    _DESCRIPTOR_SIZE,
    _DELAY_IMPORT_DIRECTORY_INDEX,
    _MAGIC_PE32,
    _MAGIC_PE32_PLUS,
)


# =================================================================
# Byte-level builders
# =================================================================

def _build_descriptor(
    attributes: int = 0x01,
    dll_name_rva: int = 0x2000,
    module_handle_rva: int = 0x3000,
    iat_rva: int = 0x4000,
    int_rva: int = 0x5000,
    bound_iat_rva: int = 0,
    unload_iat_rva: int = 0,
    timestamp: int = 0,
) -> bytes:
    """Build a 32-byte IMAGE_DELAY_IMPORT_DESCRIPTOR."""
    return struct.pack(
        "<IIIIIIII",
        attributes, dll_name_rva, module_handle_rva,
        iat_rva, int_rva, bound_iat_rva, unload_iat_rva,
        timestamp,
    )


def _zero_descriptor() -> bytes:
    """Build a zero descriptor (array terminator)."""
    return b"\x00" * _DESCRIPTOR_SIZE


def _pack_dword(value: int) -> bytes:
    return struct.pack("<I", value)


def _pack_qword(value: int) -> bytes:
    return struct.pack("<Q", value)


def _build_int_iat_array_32(thunks: List[int]) -> bytes:
    """Build a DWORD-sized thunk array terminated by a NULL DWORD."""
    return b"".join(_pack_dword(t) for t in thunks) + _pack_dword(0)


def _build_int_iat_array_64(thunks: List[int]) -> bytes:
    """Build a QWORD-sized thunk array terminated by a NULL QWORD."""
    return b"".join(_pack_qword(t) for t in thunks) + _pack_qword(0)


def _build_import_by_name(hint: int, name: str) -> bytes:
    """Build an IMAGE_IMPORT_BY_NAME structure: WORD hint + ASCIIZ name."""
    return struct.pack("<H", hint) + name.encode("ascii") + b"\x00"


def _asciiz(s: str) -> bytes:
    return s.encode("ascii") + b"\x00"


# Bit patterns for ordinal vs name thunks
def _ordinal_thunk_32(ordinal: int) -> int:
    return 0x80000000 | ordinal


def _ordinal_thunk_64(ordinal: int) -> int:
    return 0x8000000000000000 | ordinal


# =================================================================
# Fake PE object
# =================================================================

class _FakeDataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _FakeOptHdr:
    def __init__(
        self,
        delay_dir: Optional[_FakeDataDir],
        magic: int = _MAGIC_PE32_PLUS,
    ):
        self.Magic = magic
        # DATA_DIRECTORY needs at least 14 entries (index 13 is delay-load)
        self.DATA_DIRECTORY = [None] * 14
        if delay_dir is not None:
            self.DATA_DIRECTORY[_DELAY_IMPORT_DIRECTORY_INDEX] = delay_dir


class _FakePE:
    """
    Minimal duck-typed pe object exposing OPTIONAL_HEADER, DATA_DIRECTORY,
    and get_data(rva, size).

    get_data handles offset reads: if a requested (rva, size) range falls
    inside a stored buffer (looked up by the buffer's base RVA), the
    appropriate slice is returned. This matches real pefile behaviour
    where the parser walks thunk arrays one element at a time with
    incrementing RVAs.
    """
    def __init__(
        self,
        delay_rva: int = 0,
        delay_size: int = 0,
        is_64bit: bool = True,
        data_by_rva: Optional[Dict[int, bytes]] = None,
        raise_on_get_data: Optional[Exception] = None,
        raise_for_rva: Optional[int] = None,
    ):
        magic = _MAGIC_PE32_PLUS if is_64bit else _MAGIC_PE32
        if delay_rva == 0 and delay_size == 0:
            self.OPTIONAL_HEADER = _FakeOptHdr(None, magic=magic)
        else:
            self.OPTIONAL_HEADER = _FakeOptHdr(
                _FakeDataDir(delay_rva, delay_size), magic=magic,
            )
        self._data = data_by_rva or {}
        self._raise = raise_on_get_data
        self._raise_for_rva = raise_for_rva

    def get_data(self, rva: int, size: int) -> bytes:
        if self._raise is not None:
            if self._raise_for_rva is None or self._raise_for_rva == rva:
                raise self._raise

        candidates = sorted(
            (base for base in self._data if base <= rva),
            reverse=True,
        )
        for base in candidates:
            buf = self._data[base]
            offset = rva - base
            if offset <= len(buf):
                # Returns the available slice; may be empty if offset == len(buf)
                # or if buf itself is empty. Parser short-read detection handles this.
                return buf[offset:offset + size]

        raise ValueError(f"no fixture data covers rva {rva:#x} size {size}")


# =================================================================
# _locate_delay_import_directory
# =================================================================

class TestLocator:

    def test_no_data_directory_returns_none(self):
        pe = type("FakePE", (), {})()
        assert _locate_delay_import_directory(pe) is None

    def test_index_error_returns_none(self):
        class _PE:
            class OPTIONAL_HEADER:
                DATA_DIRECTORY = []
        assert _locate_delay_import_directory(_PE) is None

    def test_attribute_error_returns_none(self):
        class _PE:
            class OPTIONAL_HEADER:
                pass
        assert _locate_delay_import_directory(_PE) is None

    def test_zero_rva_returns_none(self):
        pe = _FakePE(delay_rva=0, delay_size=100)
        assert _locate_delay_import_directory(pe) is None

    def test_zero_size_returns_none(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=0)
        assert _locate_delay_import_directory(pe) is None

    def test_valid_directory_returns_rva_size(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        assert _locate_delay_import_directory(pe) == (0x1000, 64)

    def test_type_error_in_int_cast_returns_none(self):
        class _BadDir:
            VirtualAddress = "not an int"
            Size = 64

        class _PE:
            class OPTIONAL_HEADER:
                DATA_DIRECTORY = [None] * 14
        _PE.OPTIONAL_HEADER.DATA_DIRECTORY[13] = _BadDir()
        assert _locate_delay_import_directory(_PE) is None


# =================================================================
# _is_pe32_plus
# =================================================================

class TestIsPe32Plus:

    def test_pe32_plus_magic_returns_true(self):
        pe = _FakePE(is_64bit=True)
        assert _is_pe32_plus(pe) is True

    def test_pe32_magic_returns_false(self):
        pe = _FakePE(is_64bit=False)
        assert _is_pe32_plus(pe) is False

    def test_missing_optional_header_returns_false(self):
        pe = type("FakePE", (), {})()
        assert _is_pe32_plus(pe) is False

    def test_invalid_magic_returns_false(self):
        class _BadOH:
            Magic = "not an int"

        class _PE:
            OPTIONAL_HEADER = _BadOH()
        assert _is_pe32_plus(_PE) is False


# =================================================================
# _decode_descriptor and _is_zero_descriptor
# =================================================================

class TestDecodeDescriptor:

    def test_valid_descriptor_decoded(self):
        buf = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            module_handle_rva=0x3000,
            iat_rva=0x4000,
            int_rva=0x5000,
            bound_iat_rva=0x6000,
            unload_iat_rva=0,
            timestamp=0xDEADBEEF,
        )
        d = _decode_descriptor(buf, index=0)
        assert d is not None
        assert d["attributes"] == 0x01
        assert d["attributes_v1"] is True
        assert d["dll_name_rva"] == 0x2000
        assert d["module_handle_rva"] == 0x3000
        assert d["iat_rva"] == 0x4000
        assert d["int_rva"] == 0x5000
        assert d["bound_iat_rva"] == 0x6000
        assert d["unload_iat_rva"] == 0
        assert d["timestamp"] == 0xDEADBEEF
        assert d["is_bound"] is True
        assert d["imports"] == []
        assert d["errors"] == []

    def test_v0_descriptor_attributes_v1_false(self):
        buf = _build_descriptor(attributes=0x00)
        d = _decode_descriptor(buf, index=0)
        assert d["attributes"] == 0
        assert d["attributes_v1"] is False

    def test_unbound_descriptor(self):
        buf = _build_descriptor(bound_iat_rva=0)
        d = _decode_descriptor(buf, index=0)
        assert d["is_bound"] is False

    def test_too_short_buffer_returns_none(self):
        assert _decode_descriptor(b"\x00" * 16, index=0) is None

    def test_zero_descriptor_recognized(self):
        d = _decode_descriptor(_zero_descriptor(), index=0)
        assert _is_zero_descriptor(d) is True

    def test_non_zero_descriptor_not_recognized_as_terminator(self):
        buf = _build_descriptor(dll_name_rva=0x2000)
        d = _decode_descriptor(buf, index=0)
        assert _is_zero_descriptor(d) is False

    def test_descriptor_unpack_failure_appends_error_and_breaks(self, monkeypatch):
        """
        Cover the defensive struct.error path in _decode_descriptor.

        Force struct.unpack_from to raise on a buffer that has passed all
        length checks, simulating a hypothetical struct module failure.
        The parser must append an indexed error tag and break the walk.
        """
        import iocx.parsers.pe_delay_imports as pdi

        real_unpack_from = struct.unpack_from

        def fake_unpack_from(fmt, buf, offset=0):
            if fmt == "<IIIIIIII":
                raise struct.error("simulated descriptor unpack failure")
            return real_unpack_from(fmt, buf, offset)

        monkeypatch.setattr(pdi.struct, "unpack_from", fake_unpack_from)

        # Buffer with valid length so it passes the pre-checks
        descriptor = _build_descriptor()
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
            },
        )
        result = build_delay_import_structure(pe)

        # Defensive path: error appended to errors[], walk broken
        assert any(
            e.startswith("descriptor_unpack_failed_at_") for e in result["errors"]
        )
        # Walk should have broken before producing any descriptors
        assert result["descriptors"] == []

    def test_dll_name_read_error_appended(self):
        """
        Cover the err-from-_read_asciiz path: non-zero dll_name_rva but the
        underlying read fails (here, unterminated). The parser appends the
        error tag and does not set dll_name or dll_name_valid.
        """
        descriptor = _build_descriptor(dll_name_rva=0x2000)
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                # DLL name buffer: filled to max scan length without a NUL.
                # _DLL_NAME_MAX_LEN is 512, so 512 bytes of 'A' triggers the
                # unterminated branch in _read_asciiz.
                0x2000: b"A" * 512,
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert "unterminated" in d["errors"]
        # The successful-read assignments must not have happened
        assert d["dll_name"] is None
        assert d["dll_name_valid"] is False


# =================================================================
# _read_thunk_array
# =================================================================

class TestReadThunkArray:

    def test_zero_rva_flags_descriptor_error(self):
        descriptor_errors = []
        truncations = []
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        result = _read_thunk_array(
            pe, 0, 8, "int", descriptor_errors, truncations,
        )
        assert result == []
        assert "int_rva_zero" in descriptor_errors
        assert truncations == []

    def test_64bit_thunk_array_terminates_at_null(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x5000: _build_int_iat_array_64([0x100, 0x200, 0x300])},
        )
        descriptor_errors = []
        truncations = []
        result = _read_thunk_array(
            pe, 0x5000, 8, "int", descriptor_errors, truncations,
        )
        assert result == [0x100, 0x200, 0x300]
        assert descriptor_errors == []
        assert truncations == []

    def test_32bit_thunk_array_terminates_at_null(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x5000: _build_int_iat_array_32([0x100, 0x200])},
        )
        descriptor_errors = []
        truncations = []
        result = _read_thunk_array(
            pe, 0x5000, 4, "int", descriptor_errors, truncations,
        )
        assert result == [0x100, 0x200]

    def test_read_failure_flags_truncation(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            raise_on_get_data=RuntimeError("simulated"),
            raise_for_rva=0x5000,
        )
        descriptor_errors = []
        truncations = []
        result = _read_thunk_array(
            pe, 0x5000, 8, "int", descriptor_errors, truncations,
        )
        assert result == []
        assert "int_read_failed" in truncations

    def test_short_read_flags_truncation(self):
        # Only 4 bytes available; need 8 for a 64-bit thunk
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x5000: b"\x01\x02\x03\x04"},
        )
        descriptor_errors = []
        truncations = []
        result = _read_thunk_array(
            pe, 0x5000, 8, "int", descriptor_errors, truncations,
        )
        assert result == []
        assert "int_truncated" in truncations

    def test_max_exceeded_flags_truncation(self, monkeypatch):
        """Hit the hard import limit without finding a NULL terminator."""
        import iocx.parsers.pe_delay_imports as pdi

        # Patch the limit down to make the test tractable
        monkeypatch.setattr(pdi, "_MAX_IMPORTS_PER_DESCRIPTOR", 5)

        # Build 6 non-NULL thunks (more than the limit)
        thunks = [0x100, 0x200, 0x300, 0x400, 0x500, 0x600]
        # Don't include a null terminator
        raw = b"".join(_pack_qword(t) for t in thunks)
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x5000: raw},
        )
        descriptor_errors = []
        truncations = []
        _read_thunk_array(
            pe, 0x5000, 8, "int", descriptor_errors, truncations,
        )
        assert "int_max_exceeded" in truncations

    def test_thunk_unpack_failure_appends_truncation_and_breaks(self, monkeypatch):
        """
        Cover lines 389-391: the defensive struct.error path in
        _read_thunk_array. Force struct.unpack_from to raise on a buffer
        that has passed all length checks, simulating a hypothetical struct
        module failure. The parser must append a tag-prefixed truncation
        marker and break the walk.
        """
        import iocx.parsers.pe_delay_imports as pdi

        real_unpack_from = struct.unpack_from

        def fake_unpack_from(fmt, buf, offset=0):
            # Only raise on QWORD reads (the 64-bit thunk format). Lets the
            # rest of the parse machinery (descriptor unpacking via "<IIIIIIII",
            # IMAGE_IMPORT_BY_NAME hint unpacking via "<H") proceed normally.
            if fmt == "<Q":
                raise struct.error("simulated thunk unpack failure")
            return real_unpack_from(fmt, buf, offset)

        monkeypatch.setattr(pdi.struct, "unpack_from", fake_unpack_from)

        descriptor_errors = []
        truncations = []
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x5000: _build_int_iat_array_64([0x100, 0x200, 0x300]),
            },
        )
        result = _read_thunk_array(
            pe, 0x5000, 8, "int", descriptor_errors, truncations,
        )

        # The unpack failure causes immediate break; no thunks accumulated.
        assert result == []
        # Tag-prefixed truncation marker appended.
        assert "int_unpack_failed" in truncations


# =================================================================
# _read_asciiz
# =================================================================

class TestReadAsciiz:

    def test_read_failure_returns_error(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            raise_on_get_data=RuntimeError("simulated"),
        )
        s, err = _read_asciiz(pe, 0x2000, 512)
        assert s is None
        assert err == "read_failed"

    def test_empty_read_returns_error(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x2000: b""},
        )
        s, err = _read_asciiz(pe, 0x2000, 512)
        assert s is None
        assert err == "empty_read"

    def test_unterminated_returns_error(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x2000: b"A" * 100},
        )
        s, err = _read_asciiz(pe, 0x2000, 100)
        assert s is None
        assert err == "unterminated"

    def test_valid_ascii(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x2000: _asciiz("kernel32.dll")},
        )
        s, err = _read_asciiz(pe, 0x2000, 512)
        assert s == "kernel32.dll"
        assert err is None

    def test_non_ascii_returns_replacement_with_flag(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x2000: b"caf\xc3\xa9\x00"},
        )
        s, err = _read_asciiz(pe, 0x2000, 512)
        assert err == "non_ascii"
        assert s is not None


# =================================================================
# _read_import_by_name
# =================================================================

class TestReadImportByName:

    def test_valid_structure_decoded(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: _build_import_by_name(0x42, "FooFunc")},
        )
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert hint == 0x42
        assert name == "FooFunc"
        assert err is None

    def test_too_short_buffer_flagged(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: b"\x42"},
        )
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert err == "name_too_short"

    def test_unterminated_name_flagged(self):
        # Hint OK but no NUL after
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: struct.pack("<H", 0x42) + b"A" * 200},
        )
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert hint == 0x42
        assert err == "name_unterminated"

    def test_read_failure_flagged(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            raise_on_get_data=RuntimeError("simulated"),
        )
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert hint is None
        assert name is None
        assert err == "name_read_failed"

    def test_non_ascii_name_flagged(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: struct.pack("<H", 0x42) + b"caf\xc3\xa9\x00"},
        )
        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert err == "name_non_ascii"
        assert hint == 0x42

    def test_import_by_name_hint_unpack_failure(self, monkeypatch):
        """
        Cover lines 459-460: the defensive struct.error path in
        _read_import_by_name when the WORD hint unpack raises. The length
        pre-check guarantees at least 3 bytes, so struct.unpack_from won't
        fail on real input; this is purely defensive against caller drift.
        """
        import iocx.parsers.pe_delay_imports as pdi

        real_unpack_from = struct.unpack_from

        def fake_unpack_from(fmt, buf, offset=0):
            # Only raise on WORD reads (the hint format). Lets the rest of
            # the parse machinery proceed normally.
            if fmt == "<H":
                raise struct.error("simulated hint unpack failure")
            return real_unpack_from(fmt, buf, offset)

        monkeypatch.setattr(pdi.struct, "unpack_from", fake_unpack_from)

        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x6000: _build_import_by_name(0x42, "Foo"),
            },
        )

        hint, name, err = _read_import_by_name(pe, 0x6000)
        assert hint is None
        assert name is None
        assert err == "hint_unpack_failed"


# =================================================================
# _decode_import_entry
# =================================================================

class TestDecodeImportEntry:

    def test_name_entry_64bit(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: _build_import_by_name(0x50, "GdipAlloc")},
        )
        entry = _decode_import_entry(
            pe, index=0, int_value=0x6000, iat_value=0x6000,
            high_bit=1 << 63, thunk_size=8,
        )
        assert entry["is_ordinal"] is False
        assert entry["hint"] == 0x50
        assert entry["name"] == "GdipAlloc"
        assert entry["name_rva"] == 0x6000
        assert entry["name_valid"] is True
        assert entry["errors"] == []

    def test_ordinal_entry_64bit(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        entry = _decode_import_entry(
            pe, index=0,
            int_value=_ordinal_thunk_64(42),
            iat_value=_ordinal_thunk_64(42),
            high_bit=1 << 63, thunk_size=8,
        )
        assert entry["is_ordinal"] is True
        assert entry["ordinal"] == 42
        assert entry["name"] is None
        assert entry["errors"] == []

    def test_ordinal_zero_flagged(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        entry = _decode_import_entry(
            pe, index=0,
            int_value=_ordinal_thunk_64(0),
            iat_value=0,
            high_bit=1 << 63, thunk_size=8,
        )
        assert entry["is_ordinal"] is True
        assert entry["ordinal"] == 0
        assert "ordinal_zero" in entry["errors"]

    def test_int_entry_missing(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        entry = _decode_import_entry(
            pe, index=0, int_value=None, iat_value=0x6000,
            high_bit=1 << 63, thunk_size=8,
        )
        assert "int_entry_missing" in entry["errors"]

    def test_int_entry_zero(self):
        pe = _FakePE(delay_rva=0x1000, delay_size=64)
        entry = _decode_import_entry(
            pe, index=0, int_value=0, iat_value=0,
            high_bit=1 << 63, thunk_size=8,
        )
        assert "int_entry_zero" in entry["errors"]

    def test_name_not_printable_flagged(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={0x6000: struct.pack("<H", 0x42) + b"Foo\x01Bar\x00"},
        )
        entry = _decode_import_entry(
            pe, index=0, int_value=0x6000, iat_value=0x6000,
            high_bit=1 << 63, thunk_size=8,
        )
        assert entry["name"] == "Foo\x01Bar"
        assert entry["name_valid"] is False
        assert "name_not_printable" in entry["errors"]

    def test_import_entry_name_read_error_propagated(self):
        """
        Cover line 329: when _read_import_by_name returns a non-None error
        tag, the entry decoder appends it to errors[] and leaves the entry
        in its default (no name, no name_valid) state.
        """
        # Build an INT thunk pointing at an IMAGE_IMPORT_BY_NAME with
        # an unterminated name string.
        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([0x6000]),
                0x5000: _build_int_iat_array_64([0x6000]),
                # IMAGE_IMPORT_BY_NAME at 0x6000: WORD hint + 1024 bytes
                # of 'A' without NUL → triggers name_unterminated.
                0x6000: struct.pack("<H", 0x42) + b"A" * 1024,
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        entry = d["imports"][0]

        # The error from _read_import_by_name is appended directly.
        assert "name_unterminated" in entry["errors"]
        # The hint was read successfully before the failure, so it's preserved.
        assert entry["hint"] == 0x42
        # name is not populated; name_valid stays False.
        assert entry["name"] is None
        assert entry["name_valid"] is False

    def test_import_entry_name_none_without_error_flagged(self, monkeypatch):
        """
        Cover line 331: defensive guard against _read_import_by_name returning
        (hint, None, None) — a combination the function does not currently
        produce, but the validator's contract handles for forward-compatibility
        against future changes to the import-by-name reader.
        """
        import iocx.parsers.pe_delay_imports as pdi

        def fake_read_import_by_name(pe, rva):
            # Return hint but no name and no error tag — the (None, None) path
            # in the caller that line 331 guards against.
            return 0x42, None, None

        monkeypatch.setattr(pdi, "_read_import_by_name", fake_read_import_by_name)

        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([0x6000]),
                0x5000: _build_int_iat_array_64([0x6000]),
                0x6000: _build_import_by_name(0x42, "Foo"),  # actual content
            },
        )
        result = build_delay_import_structure(pe)
        entry = result["descriptors"][0]["imports"][0]
        assert "name_read_failed" in entry["errors"]


# =================================================================
# build_delay_import_structure — full roundtrips
# =================================================================

class TestBuildDelayImportStructure:

    def test_no_directory_returns_none(self):
        pe = _FakePE(delay_rva=0, delay_size=0)
        assert build_delay_import_structure(pe) is None

    def test_minimal_valid_64bit_descriptor(self):
        # One descriptor, one import by name, then terminator
        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
            bound_iat_rva=0,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64, is_64bit=True,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([0x6000]),
                0x5000: _build_int_iat_array_64([0x6000]),
                0x6000: _build_import_by_name(0x10, "Foo"),
            },
        )
        result = build_delay_import_structure(pe)
        assert result is not None
        assert result["rva"] == 0x1000
        assert result["size"] == 64
        assert result["is_64bit"] is True
        assert len(result["descriptors"]) == 1
        assert result["truncations"] == []
        assert result["errors"] == []

        d = result["descriptors"][0]
        assert d["dll_name"] == "test.dll"
        assert d["dll_name_valid"] is True
        assert d["is_bound"] is False
        assert len(d["imports"]) == 1
        assert d["imports"][0]["name"] == "Foo"

    def test_bound_descriptor(self):
        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
            bound_iat_rva=0x7000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert d["is_bound"] is True
        assert d["bound_iat_rva"] == 0x7000

    def test_v0_descriptor_attributes_captured(self):
        descriptor = _build_descriptor(
            attributes=0x00,  # v0
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert d["attributes"] == 0
        assert d["attributes_v1"] is False

    def test_int_iat_length_mismatch_flagged(self):
        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                # INT has 3 entries, IAT has 2 — mismatch
                0x4000: _build_int_iat_array_64([0x100, 0x200]),
                0x5000: _build_int_iat_array_64([0x6000, 0x6020, 0x6040]),
                0x6000: _build_import_by_name(0x10, "Foo"),
                0x6020: _build_import_by_name(0x20, "Bar"),
                0x6040: _build_import_by_name(0x30, "Baz"),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert "int_iat_length_mismatch" in d["errors"]

    def test_zero_dll_name_rva_flagged(self):
        descriptor = _build_descriptor(dll_name_rva=0)
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert "dll_name_rva_zero" in d["errors"]

    def test_dll_name_not_printable_flagged(self):
        descriptor = _build_descriptor(dll_name_rva=0x2000)
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: b"kernel\x0132.dll\x00",
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        d = result["descriptors"][0]
        assert d["dll_name_valid"] is False
        assert "dll_name_not_printable" in d["errors"]

    def test_descriptor_header_read_failure(self):
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            raise_on_get_data=RuntimeError("simulated"),
            raise_for_rva=0x1000,
        )
        result = build_delay_import_structure(pe)
        assert "delay_import_descriptor_read_failed" in result["truncations"]

    def test_descriptor_unterminated_flagged(self):
        """Reach declared end with no zero terminator."""
        # 32-byte declared size, one valid descriptor (32 bytes), no terminator
        descriptor = _build_descriptor()
        pe = _FakePE(
            delay_rva=0x1000, delay_size=32,
            data_by_rva={
                0x1000: descriptor,
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        assert "delay_import_descriptor_unterminated" in result["truncations"]

    def test_truncated_descriptor_flagged(self):
        """Declared size accommodates one descriptor, but stored bytes are short."""
        # Declared size 32 (room for one descriptor), but only 16 bytes stored.
        # Parser's pre-check passes, get_data returns short, short-read detection fires.
        pe = _FakePE(
            delay_rva=0x1000, delay_size=32,
            data_by_rva={0x1000: b"\x01\x00\x00\x00" + b"\x00" * 12},
        )
        result = build_delay_import_structure(pe)
        assert "delay_import_descriptor_truncated" in result["truncations"]

    def test_max_descriptors_exceeded_flagged(self, monkeypatch):
        import iocx.parsers.pe_delay_imports as pdi
        monkeypatch.setattr(pdi, "_MAX_DESCRIPTORS", 3)

        # Build 4 non-terminating descriptors
        full = b"".join(
            _build_descriptor(dll_name_rva=0x2000 + i * 0x100)
            for i in range(4)
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=128,
            data_by_rva={
                0x1000: full,
                0x2000: _asciiz("test1.dll"),
                0x2100: _asciiz("test2.dll"),
                0x2200: _asciiz("test3.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        assert "delay_import_descriptor_max_exceeded" in result["truncations"]

    def test_32bit_pe_uses_dword_thunks(self):
        descriptor = _build_descriptor(
            attributes=0x01,
            dll_name_rva=0x2000,
            iat_rva=0x4000,
            int_rva=0x5000,
        )
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64, is_64bit=False,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_32([0x6000]),
                0x5000: _build_int_iat_array_32([0x6000]),
                0x6000: _build_import_by_name(0x10, "Foo"),
            },
        )
        result = build_delay_import_structure(pe)
        assert result["is_64bit"] is False
        assert len(result["descriptors"][0]["imports"]) == 1


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    REQUIRED_KEYS = {
        "rva", "size", "is_64bit", "descriptors", "truncations", "errors",
    }

    def test_successful_decode_has_all_required_keys(self):
        descriptor = _build_descriptor()
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_lists_are_lists(self):
        descriptor = _build_descriptor()
        pe = _FakePE(
            delay_rva=0x1000, delay_size=64,
            data_by_rva={
                0x1000: descriptor + _zero_descriptor(),
                0x2000: _asciiz("test.dll"),
                0x4000: _build_int_iat_array_64([]),
                0x5000: _build_int_iat_array_64([]),
            },
        )
        result = build_delay_import_structure(pe)
        assert isinstance(result["descriptors"], list)
        assert isinstance(result["truncations"], list)
        assert isinstance(result["errors"], list)


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_parse_produces_identical_output(self):
        descriptor = _build_descriptor()
        data = {
            0x1000: descriptor + _zero_descriptor(),
            0x2000: _asciiz("test.dll"),
            0x4000: _build_int_iat_array_64([0x6000]),
            0x5000: _build_int_iat_array_64([0x6000]),
            0x6000: _build_import_by_name(0x10, "Foo"),
        }
        results = []
        for _ in range(20):
            pe = _FakePE(
                delay_rva=0x1000, delay_size=64,
                data_by_rva=dict(data),
            )
            results.append(build_delay_import_structure(pe))
        for r in results[1:]:
            assert r == results[0]

    def test_malformed_input_deterministic(self):
        # Non-printable DLL name, truncated INT, length mismatch
        descriptor = _build_descriptor(dll_name_rva=0x2000)
        data = {
            0x1000: descriptor + _zero_descriptor(),
            0x2000: b"bad\x01\x00",
            0x4000: _build_int_iat_array_64([0x6000]),
            0x5000: _build_int_iat_array_64([0x6000, 0x6020]),
            0x6000: _build_import_by_name(0x10, "Foo"),
            0x6020: _build_import_by_name(0x20, "Bar"),
        }
        results = []
        for _ in range(20):
            pe = _FakePE(
                delay_rva=0x1000, delay_size=64,
                data_by_rva=dict(data),
            )
            results.append(build_delay_import_structure(pe))
        for r in results[1:]:
            assert r == results[0]
