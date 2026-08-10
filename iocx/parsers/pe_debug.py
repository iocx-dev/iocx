# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE debug directory.

Independent of pefile's DIRECTORY_ENTRY_DEBUG interpretation.
Pefile is used only to:
  - Locate the debug directory (RVA, size)
  - Resolve RVAs to file offsets via pe.get_data
  - Provide raw file bytes via pe.__data__ (for PointerToRawData reads)

Each entry is a 28-byte IMAGE_DEBUG_DIRECTORY:
    DWORD Characteristics
    DWORD TimeDateStamp
    WORD  MajorVersion
    WORD  MinorVersion
    DWORD Type
    DWORD SizeOfData
    DWORD AddressOfRawData    # RVA of the debug data
    DWORD PointerToRawData    # file offset of the debug data

For CodeView entries (Type == 2) we additionally decode the PDB path from
the RSDS (PDB 7.0) or NB10 (PDB 2.0) record. All other blob types are left
opaque; we report structure only.

Output contract:
    None - no debug directory present (not an error)
    dict per the documented contract (see DebugStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_DEBUG = 6
_DEBUG_DIRECTORY_INDEX = 6
_DEBUG_ENTRY_SIZE = 28  # IMAGE_DEBUG_DIRECTORY is 28 bytes

# Hard cap on debug directory entries.
_MAX_DEBUG_ENTRIES = 256

# PDB path length cap to defend against unterminated reads.
_PDB_PATH_MAX_LEN = 512
# Upper bound on CodeView blob we will read to locate the path.
_CODEVIEW_MAX_LEN = 4096

# IMAGE_DEBUG_TYPE_*
_DEBUG_TYPE_CODEVIEW = 2
_DEBUG_TYPE_NAMES = {
    0: "UNKNOWN",
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    7: "OMAP_TO_SRC",
    8: "OMAP_FROM_SRC",
    9: "BORLAND",
    10: "RESERVED10",
    11: "CLSID",
    12: "VC_FEATURE",
    13: "POGO",
    14: "ILTCG",
    15: "MPX",
    16: "REPRO",
    17: "SPGO",
    20: "EX_DLLCHARACTERISTICS",
}

# CodeView signatures
_CV_SIG_RSDS = b"RSDS"  # PDB 7.0
_CV_SIG_NB10 = b"NB10"  # PDB 2.0


def build_debug_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE debug directory.

    Returns None if no debug directory is present. Otherwise returns a
    dict per the module docstring contract. Never raises; decode failures
    produce tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_debug_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    truncations: List[str] = []
    errors: List[str] = []

    entries = _read_entries(pe, rva, size, truncations, errors)

    return {
        "rva": rva,
        "size": size,
        "entries": entries,
        "entry_count": len(entries),
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_debug_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the debug directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_DEBUG_DIRECTORY_INDEX]
        rva = int(data_dir.VirtualAddress)
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if rva == 0 or size == 0:
        return None

    return (rva, size)


# =================================================================
# Entry array
# =================================================================

def _read_entries(
    pe,
    base_rva: int,
    declared_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[Dict[str, Any]]:
    """Walk the fixed-size IMAGE_DEBUG_DIRECTORY entries."""
    entries: List[Dict[str, Any]] = []
    declared_count = declared_size // _DEBUG_ENTRY_SIZE

    if declared_size % _DEBUG_ENTRY_SIZE != 0:
        truncations.append("debug_directory_size_not_entry_aligned")

    if declared_count > _MAX_DEBUG_ENTRIES:
        truncations.append("debug_directory_entry_count_exceeds_max")
        declared_count = _MAX_DEBUG_ENTRIES

    pos = base_rva
    for index in range(declared_count):
        try:
            raw = bytes(pe.get_data(pos, _DEBUG_ENTRY_SIZE))
        except Exception:
            truncations.append("debug_entry_read_failed")
            break

        if len(raw) < _DEBUG_ENTRY_SIZE:
            truncations.append("debug_entry_truncated")
            break

        entry = _decode_entry(pe, index, raw)
        entries.append(entry)
        pos += _DEBUG_ENTRY_SIZE

    return entries


def _decode_entry(pe, index: int, raw: bytes) -> Dict[str, Any]:
    """Unpack one 28-byte IMAGE_DEBUG_DIRECTORY and enrich CodeView."""
    try:
        (characteristics, timestamp, major, minor, dtype,
         size_of_data, addr_raw, ptr_raw) = struct.unpack_from(
            "<IIHHIIII", raw, 0,
        )
    except struct.error:
        return {
            "index": index,
            "errors": ["entry_unpack_failed"],
        }

    entry: Dict[str, Any] = {
        "index": index,
        "characteristics": characteristics,
        "timestamp": timestamp,
        "major_version": major,
        "minor_version": minor,
        "type": dtype,
        "type_name": _DEBUG_TYPE_NAMES.get(dtype),
        "size_of_data": size_of_data,
        "address_of_raw_data": addr_raw,
        "pointer_to_raw_data": ptr_raw,
        "pdb_path": None,
        "cv_signature": None,
        "guid": None,
        "age": None,
        "errors": [],
    }

    if dtype == _DEBUG_TYPE_CODEVIEW:
        _enrich_codeview(pe, entry)

    return entry


# =================================================================
# CodeView enrichment
# =================================================================

def _enrich_codeview(pe, entry: Dict[str, Any]) -> None:
    """
    Read the CodeView record and extract the PDB path deterministically.

    Prefers PointerToRawData (raw file offset); falls back to
    AddressOfRawData (RVA) if the file pointer is absent.
    """
    size_of_data = entry["size_of_data"]
    read_len = min(max(size_of_data, 0) or _CODEVIEW_MAX_LEN, _CODEVIEW_MAX_LEN)

    blob = _read_codeview_blob(pe, entry, read_len)
    if blob is None:
        entry["errors"].append("codeview_read_failed")
        return

    if len(blob) < 4:
        entry["errors"].append("codeview_too_short")
        return

    signature = blob[:4]
    if signature == _CV_SIG_RSDS:
        entry["cv_signature"] = "RSDS"
        _decode_rsds(blob, entry)
    elif signature == _CV_SIG_NB10:
        entry["cv_signature"] = "NB10"
        _decode_nb10(blob, entry)
    else:
        entry["errors"].append("codeview_signature_unknown")


def _read_codeview_blob(
    pe, entry: Dict[str, Any], read_len: int,
) -> Optional[bytes]:
    """Read the CodeView blob via file pointer first, then RVA."""
    ptr_raw = entry["pointer_to_raw_data"]
    addr_raw = entry["address_of_raw_data"]

    if ptr_raw:
        raw = getattr(pe, "__data__", None)
        if raw is not None:
            try:
                data = bytes(raw)
                return data[ptr_raw:ptr_raw + read_len]
            except (TypeError, ValueError):
                pass

    if addr_raw:
        try:
            return bytes(pe.get_data(addr_raw, read_len))
        except Exception:
            return None

    return None


def _decode_rsds(blob: bytes, entry: Dict[str, Any]) -> None:
    """
    RSDS record: 'RSDS' + GUID(16) + Age(DWORD) + ASCIIZ PDB path.
    Header is 24 bytes; path follows.
    """
    if len(blob) < 24:
        entry["errors"].append("codeview_rsds_truncated")
        return

    guid_bytes = blob[4:20]
    (age,) = struct.unpack_from("<I", blob, 20)
    entry["guid"] = _format_guid(guid_bytes)
    entry["age"] = age
    entry["pdb_path"] = _extract_asciiz_path(blob, 24, entry)


def _decode_nb10(blob: bytes, entry: Dict[str, Any]) -> None:
    """
    NB10 record: 'NB10' + Offset(DWORD) + Timestamp(DWORD) + Age(DWORD)
    + ASCIIZ PDB path. Header is 16 bytes; path follows.
    """
    if len(blob) < 16:
        entry["errors"].append("codeview_nb10_truncated")
        return

    (_offset, _ts, age) = struct.unpack_from("<III", blob, 4)
    entry["age"] = age
    entry["pdb_path"] = _extract_asciiz_path(blob, 16, entry)


def _extract_asciiz_path(
    blob: bytes, start: int, entry: Dict[str, Any],
) -> Optional[str]:
    """Extract a NUL-terminated ASCII PDB path starting at `start`."""
    region = blob[start:start + _PDB_PATH_MAX_LEN]
    nul_pos = region.find(b"\x00")
    if nul_pos == -1:
        # No terminator within the cap — take what we have and flag it.
        entry["errors"].append("pdb_path_unterminated")
        candidate = region
    else:
        candidate = region[:nul_pos]

    if not candidate:
        return None

    try:
        return candidate.decode("ascii")
    except UnicodeDecodeError:
        entry["errors"].append("pdb_path_non_ascii")
        return candidate.decode("ascii", errors="replace")


def _format_guid(guid_bytes: bytes) -> Optional[str]:
    """
    Format a 16-byte CodeView GUID as the canonical mixed-endian string
    used by symbol servers (Data1/2/3 little-endian, Data4 big-endian).
    """
    if len(guid_bytes) < 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", guid_bytes, 0)
    d4 = guid_bytes[8:16]
    return "{:08X}-{:04X}-{:04X}-{}-{}".format(
        d1, d2, d3,
        d4[:2].hex().upper(),
        d4[2:].hex().upper(),
    )
