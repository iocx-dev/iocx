# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
name_not_printable is reachable only by control characters. Anything ≥ 0x80 never gets there:

Foo\x01Bar  ->  reader err: None            ->  ['name_not_printable']
Foo\xffBar  ->  reader err: name_non_ascii  ->  ['name_non_ascii']

_read_import_by_name decodes with "ascii", so a high byte raises UnicodeDecodeError and returns the name_non_ascii tag. The caller then takes the read_err is not None branch and never reaches the printability check.
"""

from __future__ import annotations
import struct
from typing import Dict, List, Optional
import pytest

from iocx.parsers.pe_imports import (
    build_import_structure, _decode_import_entry, _read_import_by_name,
    _IMPORT_DIRECTORY_INDEX, _MAGIC_PE32_PLUS,
)

_HIGH_BIT_64 = 1 << 63


# =================================================================
# Builders
# =================================================================

def _import_by_name(hint: int, name_bytes: bytes) -> bytes:
    """IMAGE_IMPORT_BY_NAME with a raw byte name, so non-ASCII is expressible."""
    return struct.pack("<H", hint) + name_bytes + b"\x00"


def _descriptor(original_first_thunk=0x3000, timestamp=0, forwarder_chain=0,
                name_rva=0x2000, first_thunk=0x4000) -> bytes:
    return struct.pack("<IIIII", original_first_thunk, timestamp,
                       forwarder_chain, name_rva, first_thunk)


def _thunks64(values: List[int]) -> bytes:
    return b"".join(struct.pack("<Q", v) for v in values) + struct.pack("<Q", 0)


class _DataDir:
    def __init__(self, rva, size):
        self.VirtualAddress = rva
        self.Size = size

class _OptHdr:
    def __init__(self, d):
        self.Magic = _MAGIC_PE32_PLUS
        self.DATA_DIRECTORY = [None] * 16
        self.DATA_DIRECTORY[_IMPORT_DIRECTORY_INDEX] = d

class _FakePE:
    def __init__(self, data: Dict[int, bytes],
                 import_rva: int = 0x1000, import_size: int = 60):
        self.OPTIONAL_HEADER = _OptHdr(_DataDir(import_rva, import_size))
        self._data = data
    def get_data(self, rva, size):
        for base in sorted((b for b in self._data if b <= rva), reverse=True):
            buf = self._data[base]
            offset = rva - base
            if offset <= len(buf):
                return buf[offset:offset + size]
        raise ValueError(f"no fixture data covers rva {rva:#x}")


def _entry_for(name_bytes: bytes) -> Dict:
    """Decode a single by-name import whose symbol is the given raw bytes."""
    pe = _FakePE({0x5000: _import_by_name(1, name_bytes)})
    return _decode_import_entry(pe, 0, 0x5000, _HIGH_BIT_64)


# =================================================================
# The branch
# =================================================================

class TestNameNotPrintable:
    """
    `name_not_printable` is reachable ONLY by control characters.

    A byte >= 0x80 never gets here: _read_import_by_name decodes with
    "ascii", raises UnicodeDecodeError, and returns the tag `name_non_ascii`
    - so the caller takes the `read_err is not None` branch instead. A test
    written with \\xff (the obvious "non-printable" choice) would therefore
    exercise a completely different branch and pass while proving nothing
    about this one.
    """

    @pytest.mark.parametrize("byte,label", [
        (0x01, "SOH"),
        (0x09, "TAB"),
        (0x0A, "LF"),
        (0x0D, "CR"),
        (0x1F, "US - last control char below the printable range"),
        (0x7F, "DEL - just above the printable range"),
    ])
    def test_control_characters_are_flagged(self, byte, label):
        entry = _entry_for(b"Foo" + bytes([byte]) + b"Bar")
        assert entry["errors"] == ["name_not_printable"], label
        assert entry["name_valid"] is False

    def test_name_is_still_recorded(self):
        """
        The decoded string is preserved rather than discarded - a consumer
        needs it to see WHAT was malformed, and the control byte survives
        the round trip intact.
        """
        entry = _entry_for(b"Foo\x01Bar")
        assert entry["name"] == "Foo\x01Bar"
        assert entry["name_rva"] == 0x5000
        assert entry["hint"] == 1

    def test_wholly_non_printable_name(self):
        entry = _entry_for(b"\x01\x02\x03")
        assert entry["errors"] == ["name_not_printable"]

    def test_leading_and_trailing_control_chars(self):
        for raw in (b"\x01Foo", b"Foo\x01"):
            assert _entry_for(raw)["errors"] == ["name_not_printable"]


class TestPrintableBoundary:
    """
    The regex range is [\\x20-\\x7E]. These pin both edges, so widening or
    narrowing it by one is caught.
    """

    @pytest.mark.parametrize("byte,label", [
        (0x20, "SPACE - first printable"),
        (0x7E, "TILDE - last printable"),
    ])
    def test_boundary_bytes_are_accepted(self, byte, label):
        entry = _entry_for(b"Foo" + bytes([byte]) + b"Bar")
        assert entry["errors"] == [], label
        assert entry["name_valid"] is True

    @pytest.mark.parametrize("byte,label", [
        (0x1F, "one below SPACE"),
        (0x7F, "one above TILDE"),
    ])
    def test_bytes_just_outside_are_rejected(self, byte, label):
        entry = _entry_for(b"Foo" + bytes([byte]) + b"Bar")
        assert entry["errors"] == ["name_not_printable"], label


class TestNotConfusedWithNonAscii:
    """
    The negative controls. Without these, a mutation collapsing
    name_not_printable into name_non_ascii (or vice versa) would pass.
    """

    @pytest.mark.parametrize("byte", [0x80, 0xC3, 0xFF])
    def test_high_bytes_yield_non_ascii_not_not_printable(self, byte):
        entry = _entry_for(b"Foo" + bytes([byte]) + b"Bar")
        assert entry["errors"] == ["name_non_ascii"]
        assert "name_not_printable" not in entry["errors"]

    def test_the_two_tags_come_from_different_layers(self):
        """
        name_non_ascii originates in _read_import_by_name (a read fault);
        name_not_printable in _decode_import_entry (a content check). The
        first short-circuits the second.
        """
        pe_high = _FakePE({0x5000: _import_by_name(1, b"Foo\xffBar")})
        _, _, err_high = _read_import_by_name(pe_high, 0x5000)
        assert err_high == "name_non_ascii"

        pe_ctrl = _FakePE({0x5000: _import_by_name(1, b"Foo\x01Bar")})
        _, _, err_ctrl = _read_import_by_name(pe_ctrl, 0x5000)
        assert err_ctrl is None          # reader is satisfied
        assert _entry_for(b"Foo\x01Bar")["errors"] == ["name_not_printable"]

    def test_empty_name_takes_its_own_branch(self):
        """name_empty is checked before printability, so an empty string
        never reports as non-printable."""
        entry = _entry_for(b"")
        assert entry["errors"] == ["name_empty"]

    def test_ordinal_imports_never_reach_the_check(self):
        pe = _FakePE({})
        entry = _decode_import_entry(pe, 0, _HIGH_BIT_64 | 42, _HIGH_BIT_64)
        assert entry["errors"] == []
        assert entry["name"] is None


class TestEndToEnd:
    """The branch reached through the full parse, not just the helper."""

    def test_non_printable_import_name_surfaces_in_the_structure(self):
        pe = _FakePE({
            0x1000: _descriptor() + b"\x00" * 20,
            0x2000: b"KERNEL32.dll\x00",
            0x3000: _thunks64([0x5000]),
            0x5000: _import_by_name(0x10, b"Load\x01Library"),
        })
        out = build_import_structure(pe)
        entry = out["descriptors"][0]["imports"][0]
        assert entry["errors"] == ["name_not_printable"]
        assert entry["name"] == "Load\x01Library"
        assert entry["name_valid"] is False
        # The descriptor itself is otherwise clean - single anomaly.
        assert out["descriptors"][0]["errors"] == []
        assert out["truncations"] == []

    def test_mixed_valid_and_non_printable_entries(self):
        pe = _FakePE({
            0x1000: _descriptor() + b"\x00" * 20,
            0x2000: b"KERNEL32.dll\x00",
            0x3000: _thunks64([0x5000, 0x5020, 0x5040]),
            0x5000: _import_by_name(1, b"GoodName"),
            0x5020: _import_by_name(2, b"Bad\x01Name"),
            0x5040: _import_by_name(3, b"AlsoGood"),
        })
        out = build_import_structure(pe)
        imports = out["descriptors"][0]["imports"]
        assert [e["errors"] for e in imports] == [[], ["name_not_printable"], []]
        assert [e["name_valid"] for e in imports] == [True, False, True]
