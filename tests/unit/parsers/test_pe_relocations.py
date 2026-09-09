# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_relocations.

Strategy:
- Byte-level fixture builders construct IMAGE_BASE_RELOCATION blocks and
  their WORD entries (4-bit type in the high nibble, 12-bit offset in the
  low bits) directly via struct.pack.
- Fake PE objects with a controlled OPTIONAL_HEADER, DATA_DIRECTORY[5],
  and get_data() responses isolate parser logic from pefile.
- Determinism tests assert byte-for-byte stable output across runs.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

import pytest

from iocx.parsers.pe_relocations import (
    build_relocation_structure,
    _decode_block,
    _locate_reloc_directory,
    _read_blocks,
    _BLOCK_HEADER_SIZE,
    _ENTRY_SIZE,
    _MAX_ENTRIES_PER_BLOCK,
    _RELOC_DIRECTORY_INDEX,
    _RELOC_TYPE_NAMES,
    _MAX_BLOCKS,
)


# =================================================================
# Byte-level builders
# =================================================================

def _pack_entry(reloc_type: int, offset: int) -> bytes:
    """One WORD relocation entry: 4-bit type high nibble, 12-bit offset."""
    return struct.pack("<H", ((reloc_type & 0xF) << 12) | (offset & 0x0FFF))


def _build_block(page_rva: int, entries: List[Tuple[int, int]]) -> bytes:
    """Build an IMAGE_BASE_RELOCATION block: 8-byte header + WORD entries."""
    body = b"".join(_pack_entry(t, off) for t, off in entries)
    size_of_block = _BLOCK_HEADER_SIZE + len(body)
    return struct.pack("<II", page_rva, size_of_block) + body


def _build_block_raw(page_rva: int, size_of_block: int, body: bytes = b"") -> bytes:
    """Build a block with an explicit (possibly malformed) SizeOfBlock."""
    return struct.pack("<II", page_rva, size_of_block) + body


# =================================================================
# Fake PE object
# =================================================================

class _FakeDataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _FakeOptHdr:
    def __init__(self, reloc_dir: Optional[_FakeDataDir]):
        # DATA_DIRECTORY needs at least 6 entries (index 5 is base-reloc)
        self.DATA_DIRECTORY = [None] * 16
        if reloc_dir is not None:
            self.DATA_DIRECTORY[_RELOC_DIRECTORY_INDEX] = reloc_dir


class _FakePE:
    """
    Minimal duck-typed pe object exposing OPTIONAL_HEADER, DATA_DIRECTORY,
    and get_data(rva, size). RVA == offset into the backing image buffer;
    get_data raises on an unmapped RVA (as pefile does) and otherwise
    clamps the read to the buffer.
    """

    def __init__(self, image: bytes = b"",
                 reloc_dir: Optional[_FakeDataDir] = None,
                 has_optional_header: bool = True):
        self._image = bytearray(image)
        if has_optional_header:
            self.OPTIONAL_HEADER = _FakeOptHdr(reloc_dir)

    def get_data(self, rva: int, size: int) -> bytes:
        if rva < 0 or rva > len(self._image):
            raise ValueError("unmapped RVA")
        return bytes(self._image[rva:rva + size])


def _pe_with_reloc(blocks: bytes, base_rva: int = 0x1000,
                   dir_size: Optional[int] = None,
                   image_size: int = 0x8000) -> _FakePE:
    """Place `blocks` at base_rva in a zeroed image and point dir 5 at it."""
    if dir_size is None:
        dir_size = len(blocks)
    image = bytearray(image_size)
    image[base_rva:base_rva + len(blocks)] = blocks
    return _FakePE(bytes(image), _FakeDataDir(base_rva, dir_size))


# =================================================================
# _locate_reloc_directory
# =================================================================

class TestLocator:
    def test_valid_returns_tuple(self):
        pe = _FakePE(reloc_dir=_FakeDataDir(0x1000, 0x40))
        assert _locate_reloc_directory(pe) == (0x1000, 0x40)

    def test_zero_rva_returns_none(self):
        pe = _FakePE(reloc_dir=_FakeDataDir(0, 0x40))
        assert _locate_reloc_directory(pe) is None

    def test_zero_size_returns_none(self):
        pe = _FakePE(reloc_dir=_FakeDataDir(0x1000, 0))
        assert _locate_reloc_directory(pe) is None

    def test_empty_directory_returns_none(self):
        pe = _FakePE(reloc_dir=_FakeDataDir(0, 0))
        assert _locate_reloc_directory(pe) is None

    def test_missing_optional_header_returns_none(self):
        pe = _FakePE(has_optional_header=False)
        assert _locate_reloc_directory(pe) is None

    def test_missing_entry_returns_none(self):
        # OPTIONAL_HEADER present but dir 5 left as None
        pe = _FakePE()
        assert _locate_reloc_directory(pe) is None


# =================================================================
# _decode_block
# =================================================================

class TestDecodeBlock:
    def test_type_and_offset_decoding(self):
        block_bytes = _build_block(0x2000, [(3, 0x10), (10, 0x20)])
        pe = _pe_with_reloc(block_bytes)
        trunc: List[str] = []
        block = _decode_block(pe, 0, 0x1000, 0x2000, len(block_bytes),
                              0x1000 + len(block_bytes), trunc)
        assert block["entries"][0] == {
            "type": 3, "type_name": "HIGHLOW", "offset": 0x10, "rva": 0x2010}
        assert block["entries"][1] == {
            "type": 10, "type_name": "DIR64", "offset": 0x20, "rva": 0x2020}
        assert block["entry_count"] == 2
        assert block["errors"] == []

    def test_unknown_type_name_is_none(self):
        # type 11 has no label in _RELOC_TYPE_NAMES
        block_bytes = _build_block(0x2000, [(11, 0x4)])
        pe = _pe_with_reloc(block_bytes)
        block = _decode_block(pe, 0, 0x1000, 0x2000, len(block_bytes),
                              0x1000 + len(block_bytes), [])
        assert block["entries"][0]["type"] == 11
        assert block["entries"][0]["type_name"] is None

    def test_size_of_block_too_small(self):
        block = _decode_block(_FakePE(), 0, 0x1000, 0x2000, 4, 0x2000, [])
        assert block["errors"] == ["size_of_block_too_small"]
        assert block["entries"] == []

    def test_size_of_block_not_word_aligned(self):
        # header(8) + 3 bytes -> not a whole number of WORD entries
        body = _pack_entry(3, 0x10) + b"\x01"
        raw = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + len(body), body)
        pe = _pe_with_reloc(raw)
        block = _decode_block(pe, 0, 0x1000, 0x2000, len(raw),
                              0x1000 + len(raw), [])
        assert "size_of_block_not_word_aligned" in block["errors"]

    def test_entry_count_exceeds_max_is_tagged_and_capped(self):
        # SizeOfBlock large enough to declare > _MAX_ENTRIES_PER_BLOCK entries
        big = _BLOCK_HEADER_SIZE + (_MAX_ENTRIES_PER_BLOCK + 100) * _ENTRY_SIZE
        image = bytearray(0x1000 + big + 0x10)
        pe = _FakePE(bytes(image), _FakeDataDir(0x1000, big))
        block = _decode_block(pe, 0, 0x1000, 0x2000, big, 0x1000 + big, [])
        assert "entry_count_exceeds_max" in block["errors"]
        assert block["entry_count"] <= _MAX_ENTRIES_PER_BLOCK


# =================================================================
# _read_blocks
# =================================================================

class TestReadBlocks:
    def test_two_blocks_walked(self):
        blocks = _build_block(0x2000, [(3, 0x10), (0, 0)])
        blocks += _build_block(0x3000, [(3, 0x4)])
        pe = _pe_with_reloc(blocks)
        trunc: List[str] = []
        errs: List[str] = []
        out = _read_blocks(pe, 0x1000, len(blocks), trunc, errs)
        assert len(out) == 2
        assert [b["page_rva"] for b in out] == [0x2000, 0x3000]
        assert trunc == [] and errs == []

    def test_block_too_small_stops_walk_no_infinite_loop(self):
        raw = _build_block_raw(0x2000, 4)  # non-advancing SizeOfBlock
        pe = _pe_with_reloc(raw, dir_size=0x100)
        out = _read_blocks(pe, 0x1000, 0x100, [], [])
        assert len(out) == 1
        assert out[0]["errors"] == ["size_of_block_too_small"]

    def test_header_truncated_when_window_too_small(self):
        # declared directory window shorter than an 8-byte header
        pe = _pe_with_reloc(b"\x00\x20\x00\x00", dir_size=4)
        trunc: List[str] = []
        out = _read_blocks(pe, 0x1000, 4, trunc, [])
        assert out == []
        assert "relocation_block_header_truncated" in trunc

    def test_entries_truncated_when_block_exceeds_window(self):
        header = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 0x40)
        partial = header + _pack_entry(3, 0x4)  # only one entry present
        pe = _pe_with_reloc(partial, dir_size=10)  # header + 1 entry
        trunc: List[str] = []
        _read_blocks(pe, 0x1000, 10, trunc, [])
        assert "relocation_entries_exceed_directory" in trunc

    def test_short_header_read_is_tagged(self):
        """get_data returns fewer than 8 bytes without raising."""
        trunc = []
        pe = _FakePE(bytes(0x1004), _FakeDataDir(0x1000, 0x40))
        out = _read_blocks(pe, 0x1000, 0x40, trunc, [])
        assert out == []
        assert trunc == ["relocation_block_header_truncated"]

    def test_entries_read_failure_is_tagged(self):
        """get_data raises on the entry region but not the header."""
        class _RaisingPE(_FakePE):
            def get_data(self, rva, size):
                if rva >= 0x1008:
                    raise ValueError("unmapped")
                return super().get_data(rva, size)
        blocks = _build_block(0x2000, [(3, 0x10), (3, 0x20)])
        image = bytearray(0x8000)
        image[0x1000:0x1000 + len(blocks)] = blocks
        pe = _RaisingPE(bytes(image), _FakeDataDir(0x1000, len(blocks)))
        out = build_relocation_structure(pe)
        assert "relocation_entries_read_failed" in out["truncations"]
        assert out["blocks"][0]["entries"] == []

    def test_entries_short_read_is_tagged(self):
        """Header fits the window, but the image ends mid-entry-array."""
        hdr = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 0x10)
        image = bytearray(0x1010)          # ends 8 bytes into the entries
        image[0x1000:0x1008] = hdr
        pe = _FakePE(bytes(image), _FakeDataDir(0x1000, _BLOCK_HEADER_SIZE + 0x10))
        out = build_relocation_structure(pe)
        assert "relocation_entries_truncated" in out["truncations"]
        assert out["blocks"][0]["entry_count"] == 4   # only what was readable

    def test_block_count_cap_is_tagged(self):
        """65536 minimal blocks exhaust the walk limit."""
        one = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE)
        many = one * _MAX_BLOCKS
        image = bytearray(0x1000 + len(many) + 0x10)
        image[0x1000:0x1000 + len(many)] = many
        pe = _FakePE(bytes(image), _FakeDataDir(0x1000, len(many)))
        out = build_relocation_structure(pe)
        assert out["block_count"] == _MAX_BLOCKS
        assert "relocation_block_max_exceeded" in out["truncations"]


# =================================================================
# build_relocation_structure — full roundtrips
# =================================================================

class TestBuildRelocationStructure:
    def test_absent_directory_returns_none(self):
        assert build_relocation_structure(_FakePE()) is None

    def test_basic_roundtrip(self):
        blocks = _build_block(0x2000, [(3, 0x10), (10, 0x20), (0, 0)])
        blocks += _build_block(0x3000, [(3, 0x4), (3, 0x8)])
        out = build_relocation_structure(_pe_with_reloc(blocks))
        assert out["block_count"] == 2
        assert out["entry_count"] == 5
        assert out["rva"] == 0x1000
        assert out["errors"] == [] and out["truncations"] == []

    def test_dir64_page(self):
        block = _build_block(0x5000, [(10, 0x0), (10, 0x8), (0, 0)])
        out = build_relocation_structure(_pe_with_reloc(block))
        types = {e["type_name"] for e in out["blocks"][0]["entries"]}
        assert "DIR64" in types and "ABSOLUTE" in types

    def test_all_absolute_padding(self):
        block = _build_block(0x2000, [(0, 0), (0, 0), (0, 0)])
        out = build_relocation_structure(_pe_with_reloc(block))
        assert all(e["type"] == 0 for e in out["blocks"][0]["entries"])
        assert out["errors"] == []

    def test_never_raises_on_short_read(self):
        # dir points beyond the backing image -> tombstone, no exception
        pe = _FakePE(bytes(0x100), _FakeDataDir(0x2000, 0x40))
        out = build_relocation_structure(pe)
        assert out is not None
        assert out["truncations"] == ["relocation_block_read_failed"]  # read failure recorded


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:
    def _out(self):
        blocks = _build_block(0x2000, [(3, 0x10), (0, 0)])
        return build_relocation_structure(_pe_with_reloc(blocks))

    def test_required_top_level_keys(self):
        out = self._out()
        for key in ("rva", "size", "blocks", "block_count",
                    "entry_count", "truncations", "errors"):
            assert key in out

    def test_block_keys(self):
        block = self._out()["blocks"][0]
        for key in ("index", "block_rva", "page_rva", "size_of_block",
                    "entry_count", "entries", "errors"):
            assert key in block

    def test_entry_keys(self):
        entry = self._out()["blocks"][0]["entries"][0]
        assert set(entry) == {"type", "type_name", "offset", "rva"}

    def test_json_serializable(self):
        import json
        json.dumps(self._out())  # must not raise


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def test_repeated_calls_identical(self):
        import json
        blocks = _build_block(0x2000, [(3, 0x10), (10, 0x20), (0, 0)])
        blocks += _build_block(0x3000, [(3, 0x4)])
        a = build_relocation_structure(_pe_with_reloc(blocks))
        b = build_relocation_structure(_pe_with_reloc(blocks))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_adversarial_output_stable(self):
        import json
        raw = _build_block_raw(0x2000, 4)
        a = build_relocation_structure(_pe_with_reloc(raw, dir_size=0x100))
        b = build_relocation_structure(_pe_with_reloc(raw, dir_size=0x100))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
