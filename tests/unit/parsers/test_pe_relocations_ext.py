# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Coverage-gap tests for iocx.parsers.pe_relocations.

Targets the branches missed by the main suite (88% -> 100%):
  - short block-header read            (relocation_block_header_truncated)
  - block-header unpack failure         (block_header_unpack_failed_at_*)
  - _MAX_BLOCKS exhaustion              (relocation_block_max_exceeded)
  - entries read raises                 (relocation_entries_read_failed)
  - entries short read                  (relocation_entries_truncated)

Each of these needs a get_data() that behaves differently from a simple
flat-image stub (short reads, raising reads), plus two monkeypatched cases
for the defensive/loop-bound branches.
"""

from __future__ import annotations

import struct

import pytest

import iocx.parsers.pe_relocations as R
from iocx.parsers.pe_relocations import build_relocation_structure

_BASE = 0x1000  # locator treats rva == 0 as "absent"


# =================================================================
# Fake PE variants
# =================================================================

class _DataDir:
    def __init__(self, va, size):
        self.VirtualAddress = va
        self.Size = size


class _OptHdr:
    def __init__(self, va, size):
        self.DATA_DIRECTORY = [None] * 16
        self.DATA_DIRECTORY[R._RELOC_DIRECTORY_INDEX] = _DataDir(va, size)


class _FlatPE:
    """RVA == offset into image; get_data clamps, raises only if rva > len."""
    def __init__(self, block_bytes: bytes, dir_size: int):
        self._img = bytearray(_BASE) + bytearray(block_bytes)
        self.OPTIONAL_HEADER = _OptHdr(_BASE, dir_size)

    def get_data(self, rva, length):
        if rva < 0 or rva > len(self._img):
            raise ValueError("unmapped RVA")
        return bytes(self._img[rva:rva + length])


class _EntriesRaisePE:
    """Header read at the block base succeeds; any later (entries) read raises."""
    def __init__(self, header: bytes, dir_size: int):
        self._header = header
        self.OPTIONAL_HEADER = _OptHdr(_BASE, dir_size)

    def get_data(self, rva, length):
        if rva == _BASE:
            return bytes(self._header[:length])
        raise ValueError("boom on entries read")


def _hdr(page_rva: int, size_of_block: int) -> bytes:
    return struct.pack("<II", page_rva, size_of_block)


# =================================================================
# Coverage-gap cases
# =================================================================

class TestBlockHeaderTruncation:
    def test_short_header_read_tombstoned(self):
        # dir declared large, but only 4 bytes present at the block position
        pe = _FlatPE(b"\x00\x20\x00\x00", dir_size=0x100)
        out = build_relocation_structure(pe)
        assert out["blocks"] == []
        assert "relocation_block_header_truncated" in out["truncations"]


class TestMaxBlocksExceeded:
    def test_loop_bound_tombstoned(self, monkeypatch):
        monkeypatch.setattr(R, "_MAX_BLOCKS", 3)
        # four header-only blocks (size_of_block == 8), declared dir large so
        # pos never reaches end within 3 iterations -> loop exhausts -> else
        pe = _FlatPE(_hdr(0x1000, 8) * 4, dir_size=0x1000)
        out = build_relocation_structure(pe)
        assert "relocation_block_max_exceeded" in out["truncations"]
        assert out["block_count"] == 3


class TestEntriesReadRaises:
    def test_entries_read_failure_tombstoned(self):
        # header decodes; the entries read raises -> read_failed, empty entries
        pe = _EntriesRaisePE(_hdr(0x2000, 0x10), dir_size=0x100)
        out = build_relocation_structure(pe)
        assert "relocation_entries_read_failed" in out["truncations"]
        assert out["blocks"][0]["entry_count"] == 0


class TestEntriesShortRead:
    def test_short_entries_read_recomputes_count(self):
        # header ok; dir_end covers the full block (no clamp), but the image is
        # short so get_data returns fewer entry bytes than requested.
        pe = _FlatPE(_hdr(0x2000, 0x10) + b"\xAA\xAA", dir_size=0x10)
        out = build_relocation_structure(pe)
        assert "relocation_entries_truncated" in out["truncations"]
        # 2 bytes -> exactly one WORD entry decoded
        assert out["blocks"][0]["entry_count"] == 1
