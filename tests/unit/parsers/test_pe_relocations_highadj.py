# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations
import struct
import pytest
from iocx.parsers.pe_relocations import (
    build_relocation_structure, _decode_block, _read_blocks,
    _BLOCK_HEADER_SIZE, _ENTRY_SIZE, _RELOC_TYPE_HIGHADJ,
)

def _pack_entry(reloc_type, offset):
    return struct.pack("<H", ((reloc_type & 0xF) << 12) | (offset & 0x0FFF))

def _build_block(page_rva, entries):
    body = b"".join(_pack_entry(t, off) for t, off in entries)
    size_of_block = _BLOCK_HEADER_SIZE + len(body)
    return struct.pack("<II", page_rva, size_of_block) + body

def _build_block_raw(page_rva, size_of_block, body=b""):
    return struct.pack("<II", page_rva, size_of_block) + body

class _FakeDataDir:
    def __init__(self, rva, size):
        self.VirtualAddress = rva; self.Size = size

class _FakeOptHdr:
    def __init__(self, reloc_dir):
        self.DATA_DIRECTORY = [None] * 16
        if reloc_dir is not None:
            self.DATA_DIRECTORY[5] = reloc_dir

class _FakePE:
    def __init__(self, image=b"", reloc_dir=None):
        self._image = bytearray(image)
        self.OPTIONAL_HEADER = _FakeOptHdr(reloc_dir)
    def get_data(self, rva, size):
        if rva < 0 or rva > len(self._image):
            raise ValueError("unmapped RVA")
        return bytes(self._image[rva:rva + size])

def _pe_with_reloc(blocks, base_rva=0x1000, dir_size=None, image_size=0x8000):
    if dir_size is None:
        dir_size = len(blocks)
    image = bytearray(image_size)
    image[base_rva:base_rva + len(blocks)] = blocks
    return _FakePE(bytes(image), _FakeDataDir(base_rva, dir_size))


# =================================================================
# Regression guard for the _RELOC_TYPE_HIGHADJ NameError
# =================================================================

class TestHighadjNameErrorRegression:

    @pytest.mark.parametrize("reloc_type", [t for t in range(16) if t != _RELOC_TYPE_HIGHADJ])
    def test_ordinary_entries_never_reference_undefined_name(self, reloc_type):
        """
        Every non-HIGHADJ type must decode cleanly. This is the direct
        regression guard for the bug where `_RELOC_TYPE_HIGHADJ` was
        referenced without being defined: because the comparison ran
        unconditionally at the end of every loop iteration (not gated behind
        an `if reloc_type == HIGHADJ` branch), it crashed on ANY entry of ANY
        type - not just HIGHADJ ones. A single entry of any type is enough to
        reach the crashing line, so this is parametrised across all 16
        possible 4-bit type values rather than picking one representative.
        """
        bb = _build_block(0x2000, [(reloc_type, 0x10)])
        pe = _pe_with_reloc(bb)
        block = _decode_block(pe, 0, 0x1000, 0x2000, len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 1
        assert block["entries"][0]["type"] == reloc_type
        assert "adjustment" not in block["entries"][0]

    def test_full_page_of_all_types_never_raises(self):
        """
        A single block containing every declared type (0-10) plus several
        unknown types, repeated to page size, must decode without raising -
        the broadest possible sweep of the crashing code path in one fixture.
        """
        entries = [(t, (i * 4) & 0xFFF) for i, t in enumerate(list(range(16)) * 20)]
        bb = _build_block(0x2000, entries)
        out = build_relocation_structure(_pe_with_reloc(bb))
        assert out is not None
        assert out["block_count"] == 1
        assert out["errors"] == []

    def test_build_relocation_structure_does_not_raise_on_any_entry(self):
        """
        End-to-end guard at the public API: the crash was reachable from
        build_relocation_structure on the very first ordinary entry, so this
        pins the full call path rather than only the internal helper.
        """
        bb = _build_block(0x2000, [(3, 0x10)])   # ordinary HIGHLOW, not HIGHADJ
        out = build_relocation_structure(_pe_with_reloc(bb))
        assert out is not None
        assert out["entry_count"] == 1


# =================================================================
# skip_next state-machine coverage
# =================================================================

class TestHighadjSkipNextLogic:
    """
    `skip_next` tracks whether the NEXT word is a raw adjustment value (the
    second slot of a HIGHADJ pair) rather than an independent type+offset
    entry. These tests drive every transition of that flag directly, rather
    than relying on the single-pair case to imply the rest.
    """

    def test_highadj_sets_skip_next_and_consumes_following_word(self):
        """HIGHADJ -> skip_next True -> next word consumed as `adjustment`,
        never decoded as its own entry, and the flag resets to False."""
        bb = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 4,
                              _pack_entry(4, 0x10) + struct.pack("<H", 0x1234))
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 1
        assert block["entries"][0]["type"] == 4
        assert block["entries"][0]["adjustment"] == 0x1234
        assert block["errors"] == []

    def test_adjustment_word_shaped_like_an_entry_is_not_redecoded(self):
        """
        The adjustment word for one HIGHADJ can itself have the bit pattern
        of a HIGHADJ entry (type nibble == 4). It must still be consumed as a
        raw value, not re-interpreted as a second HIGHADJ entry - proving
        skip_next is a state transition, not a per-word type re-check.
        """
        adjustment_shaped_like_highadj = _pack_entry(4, 0x99)
        bb = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 4,
                              _pack_entry(4, 0x10) + adjustment_shaped_like_highadj)
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 1
        # the raw 16-bit word is stored verbatim, not decoded into type/offset
        assert block["entries"][0]["adjustment"] == int.from_bytes(
            adjustment_shaped_like_highadj, "little")
        assert block["errors"] == []

    def test_two_consecutive_highadj_pairs_each_resolve_independently(self):
        """skip_next must reset after each pair so a second HIGHADJ later in
        the same block starts its own fresh pairing rather than being
        swallowed by leftover state from the first."""
        bb = _build_block_raw(
            0x2000, _BLOCK_HEADER_SIZE + 8,
            _pack_entry(4, 0x10) + struct.pack("<H", 0x1111) +
            _pack_entry(4, 0x20) + struct.pack("<H", 0x2222))
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 2
        assert block["entries"][0]["adjustment"] == 0x1111
        assert block["entries"][1]["adjustment"] == 0x2222
        assert block["errors"] == []

    def test_ordinary_entry_after_highadj_pair_is_not_skipped(self):
        """After a HIGHADJ pair completes, the next word must be decoded as
        a normal entry - skip_next must not remain stuck True."""
        bb = _build_block_raw(
            0x2000, _BLOCK_HEADER_SIZE + 6,
            _pack_entry(4, 0x10) + struct.pack("<H", 0x1234) + _pack_entry(3, 0x20))
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 2
        assert block["entries"][0]["adjustment"] == 0x1234
        assert block["entries"][1]["type"] == 3
        assert "adjustment" not in block["entries"][1]

    def test_trailing_highadj_with_no_adjustment_word_is_tagged(self):
        """HIGHADJ as the last word in the block: skip_next is still True
        when the loop ends, which must produce a tombstone, not a crash or
        a silently-dropped flag."""
        bb = _build_block(0x2000, [(4, 0x10)])
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert block["entry_count"] == 1
        assert "adjustment" not in block["entries"][0]
        assert block["errors"] == ["highadj_missing_adjustment"]

    def test_skip_next_does_not_leak_across_blocks(self):
        """A dangling HIGHADJ at the end of one block must not cause the
        FIRST word of the NEXT block to be swallowed as its adjustment -
        skip_next is local to _decode_block, reset per call."""
        block1 = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 2,
                                  _pack_entry(4, 0x10))       # dangling HIGHADJ
        block2 = _build_block(0x3000, [(3, 0x20)])            # ordinary entry
        combined = block1 + block2
        out = build_relocation_structure(_pe_with_reloc(combined))
        assert out["blocks"][0]["errors"] == ["highadj_missing_adjustment"]
        assert out["blocks"][1]["errors"] == []
        assert out["blocks"][1]["entries"][0]["type"] == 3
        assert "adjustment" not in out["blocks"][1]["entries"][0]

    def test_highadj_pair_split_by_truncated_read(self):
        """If the readable region is clamped mid-pair (the adjustment word
        falls outside the mapped image), the HIGHADJ entry must still be
        recorded and flagged as missing its adjustment, not silently lost
        or paired with garbage."""
        full = _build_block_raw(0x2000, _BLOCK_HEADER_SIZE + 4,
                                _pack_entry(4, 0x10) + struct.pack("<H", 0x1234))
        image = bytearray(0x1000 + _BLOCK_HEADER_SIZE + 2)   # ends before the 2nd word
        image[0x1000:0x1000 + _BLOCK_HEADER_SIZE + 2] = full[:_BLOCK_HEADER_SIZE + 2]
        pe = _FakePE(bytes(image), _FakeDataDir(0x1000, _BLOCK_HEADER_SIZE + 4))
        out = build_relocation_structure(pe)
        block = out["blocks"][0]
        assert "relocation_entries_truncated" in out["truncations"]
        assert block["entry_count"] == 1
        assert "adjustment" not in block["entries"][0]
        assert block["errors"] == ["highadj_missing_adjustment"]

    def test_highadj_output_key_present_only_when_paired(self):
        """The `adjustment` key must be absent entirely (not None) on any
        entry that never paired - a downstream consumer should be able to
        rely on `"adjustment" in entry` rather than checking for None."""
        bb = _build_block(0x2000, [(3, 0x10), (4, 0x20)])   # HIGHADJ last, no pair
        block = _decode_block(_pe_with_reloc(bb), 0, 0x1000, 0x2000,
                              len(bb), 0x1000 + len(bb), [])
        assert "adjustment" not in block["entries"][0]
        assert "adjustment" not in block["entries"][1]
        assert block["errors"] == ["highadj_missing_adjustment"]
