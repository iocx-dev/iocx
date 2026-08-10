# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE base-relocation table.

Independent of pefile's DIRECTORY_ENTRY_BASERELOC interpretation.
Pefile is used only to:
  - Locate the relocation directory (RVA, size)
  - Resolve RVAs to file offsets via pe.get_data

All structural fields are decoded from the raw IMAGE_BASE_RELOCATION
blocks. Each block is an 8-byte header (VirtualAddress, SizeOfBlock)
followed by (SizeOfBlock - 8) / 2 WORD entries; each entry packs a
4-bit type in the high nibble and a 12-bit offset in the low bits.

Output contract:
    None - no relocation directory present (not an error)
    dict per the documented contract (see RelocationStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
_RELOC_DIRECTORY_INDEX = 5
_BLOCK_HEADER_SIZE = 8  # IMAGE_BASE_RELOCATION header is 8 bytes
_ENTRY_SIZE = 2         # each relocation entry is a WORD

# Hard limit on relocation blocks to defend against pathological inputs
# claiming arbitrarily many. Real binaries rarely exceed a few thousand.
_MAX_BLOCKS = 65536

# Hard limit on entries per block. A single 4 KiB page can hold at most
# 2048 WORD entries after the 8-byte header, so this is generous.
_MAX_ENTRIES_PER_BLOCK = 8192

# IMAGE_REL_BASED_* type names. Values not present here are reported by
# their numeric type with type_name None; we do not invent labels.
_RELOC_TYPE_NAMES = {
    0: "ABSOLUTE",
    1: "HIGH",
    2: "LOW",
    3: "HIGHLOW",
    4: "HIGHADJ",
    5: "MACHINE_SPECIFIC_5",   # MIPS_JMPADDR / ARM_MOV32 / RISCV_HIGH20
    6: "RESERVED",
    7: "MACHINE_SPECIFIC_7",   # THUMB_MOV32 / RISCV_LOW12I
    8: "MACHINE_SPECIFIC_8",   # RISCV_LOW12S / LOONGARCH_MARK_LA
    9: "MIPS_JMPADDR16",
    10: "DIR64",
}


def build_relocation_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE base-relocation table.

    Returns None if no relocation directory is present. Otherwise returns
    a dict per the module docstring contract. Never raises; decode
    failures produce tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_reloc_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    truncations: List[str] = []
    errors: List[str] = []

    blocks = _read_blocks(pe, rva, size, truncations, errors)

    entry_count = sum(len(b["entries"]) for b in blocks)

    return {
        "rva": rva,
        "size": size,
        "blocks": blocks,
        "block_count": len(blocks),
        "entry_count": entry_count,
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_reloc_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the relocation directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_RELOC_DIRECTORY_INDEX]
        rva = int(data_dir.VirtualAddress)
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if rva == 0 or size == 0:
        return None

    return (rva, size)


# =================================================================
# Block array
# =================================================================

def _read_blocks(
    pe,
    base_rva: int,
    declared_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[Dict[str, Any]]:
    """
    Walk the array of IMAGE_BASE_RELOCATION blocks.

    Blocks are packed contiguously; each block advertises its own total
    SizeOfBlock (header + entries). We stop at the declared directory
    size and enforce a max block count to defend against pathological
    inputs. A SizeOfBlock that does not advance the cursor is fatal for
    the walk (would otherwise loop forever) and is tagged as such.
    """
    blocks: List[Dict[str, Any]] = []
    pos = base_rva
    end = base_rva + declared_size

    for index in range(_MAX_BLOCKS):
        if pos >= end:
            break

        if pos + _BLOCK_HEADER_SIZE > end:
            truncations.append("relocation_block_header_truncated")
            break

        try:
            header = bytes(pe.get_data(pos, _BLOCK_HEADER_SIZE))
        except Exception:
            truncations.append("relocation_block_read_failed")
            break

        if len(header) < _BLOCK_HEADER_SIZE:
            truncations.append("relocation_block_header_truncated")
            break

        try:
            page_rva, size_of_block = struct.unpack_from("<II", header, 0)
        except struct.error: # pragma: no cover
            errors.append(f"block_header_unpack_failed_at_{index}")
            break

        block = _decode_block(
            pe, index, pos, page_rva, size_of_block, end, truncations,
        )
        blocks.append(block)

        # Advance by the advertised block size. Guard against a size that
        # would fail to advance the cursor (0 or < header) to avoid an
        # infinite loop; such a block is structurally malformed. The
        # decoder has already tagged the block, so we just stop the walk.
        if size_of_block < _BLOCK_HEADER_SIZE:
            break

        pos += size_of_block
    else:
        truncations.append("relocation_block_max_exceeded")

    return blocks


def _decode_block(
    pe,
    index: int,
    block_rva: int,
    page_rva: int,
    size_of_block: int,
    dir_end: int,
    truncations: List[str],
) -> Dict[str, Any]:
    """Decode a single relocation block header and its WORD entries."""
    block: Dict[str, Any] = {
        "index": index,
        "block_rva": block_rva,
        "page_rva": page_rva,
        "size_of_block": size_of_block,
        "entry_count": 0,
        "entries": [],
        "errors": [],
    }

    if size_of_block < _BLOCK_HEADER_SIZE:
        block["errors"].append("size_of_block_too_small")
        return block

    entries_bytes = size_of_block - _BLOCK_HEADER_SIZE
    if entries_bytes % _ENTRY_SIZE != 0:
        # Odd trailing byte — not a whole number of WORD entries.
        block["errors"].append("size_of_block_not_word_aligned")

    declared_entries = entries_bytes // _ENTRY_SIZE
    if declared_entries > _MAX_ENTRIES_PER_BLOCK:
        block["errors"].append("entry_count_exceeds_max")
        declared_entries = _MAX_ENTRIES_PER_BLOCK

    # Clamp the readable region to the declared directory end so a block
    # advertising a SizeOfBlock past the directory cannot over-read.
    entries_start = block_rva + _BLOCK_HEADER_SIZE
    readable = max(0, min(entries_bytes, dir_end - entries_start))
    if readable < entries_bytes:
        truncations.append("relocation_entries_truncated")

    readable_entries = min(declared_entries, readable // _ENTRY_SIZE)

    try:
        raw = bytes(pe.get_data(entries_start, readable_entries * _ENTRY_SIZE))
    except Exception:
        truncations.append("relocation_entries_read_failed")
        raw = b""

    if len(raw) < readable_entries * _ENTRY_SIZE:
        truncations.append("relocation_entries_truncated")
        readable_entries = len(raw) // _ENTRY_SIZE

    for i in range(readable_entries):
        (word,) = struct.unpack_from("<H", raw, i * _ENTRY_SIZE)
        reloc_type = (word >> 12) & 0xF
        offset = word & 0x0FFF
        block["entries"].append({
            "type": reloc_type,
            "type_name": _RELOC_TYPE_NAMES.get(reloc_type),
            "offset": offset,
            "rva": page_rva + offset,
        })

    block["entry_count"] = len(block["entries"])
    return block
