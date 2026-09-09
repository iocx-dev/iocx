# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE export table.

This module is intentionally independent of pefile's DIRECTORY_ENTRY_EXPORT
interpretation. We use pefile only to:
  - Locate the export directory (RVA, size)
  - Resolve RVAs to file offsets
  - Read raw bytes via pe.get_data

All structural fields (Base, NumberOfFunctions, NumberOfNames,
AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals) are read directly
from the raw 40-byte IMAGE_EXPORT_DIRECTORY structure. The name pointer
array, name strings, and forwarder strings are also read raw.

Output contract:
    None  - no export directory present (not an error)
    dict with keys (see ExportStruct in iocx.schemas.internal_schema):
        rva, size                    - placement of the export directory
        header                       - decoded IMAGE_EXPORT_DIRECTORY fields
        functions                    - list[FunctionEntry]
        name_pointers                - list[NamePointerEntry]
        truncations                  - list[str] - parser tombstone tags
        errors                       - list[str] - top-level decode errors

Each FunctionEntry has:
        index                        - position in EAT (0..NumberOfFunctions-1)
        ordinal                      - Base + index
        address_rva                  - value from AddressOfFunctions entry
        is_forwarder                 - True if address_rva is within the
                                       export directory (per PE spec)
        forwarder                    - raw forwarder string if applicable,
                                       else None
        forwarder_valid              - structural validity of the forwarder
        name                         - resolved name if a name pointer maps
                                       to this index, else None
        name_rva                     - RVA of the name string, if any
        errors                       - per-entry decode errors

Each NamePointerEntry has:
        index                        - position in name pointer array
        name_rva                     - value from AddressOfNames entry
        ordinal_index                - value from AddressOfNameOrdinals (the
                                       index into AddressOfFunctions)
        name                         - decoded string, or None on failure
        name_valid                   - structural validity of the name
        errors                       - per-entry decode errors
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional

# IMAGE_DIRECTORY_ENTRY_EXPORT = 0
_EXPORT_DIRECTORY_INDEX = 0
_EXPORT_DIRECTORY_SIZE = 40  # IMAGE_EXPORT_DIRECTORY is 40 bytes

# Forwarder string: ASCII printable, "DllName.SymbolName" or "DllName.#Ordinal"
# Conservative bounds: name parts up to 255 chars, total up to 512.
# The symbol branch excludes a leading '#' (0x23) so an over-long ordinal
# such as "Dll.#99999999999" cannot fall through to it and be accepted as an
# ordinary symbol name. Ordinals are 16-bit, hence at most five digits.
_FORWARDER_RE = re.compile(
    r"^[\x20-\x7E]{1,255}\.(?:#\d{1,5}|[\x20-\x22\x24-\x7E][\x20-\x7E]{0,254})$"
)

# Name string: PE spec allows ASCII; we accept any printable byte range
# typical of compilers. Length cap defends against pathological inputs.
_NAME_MAX_LEN = 1024
_FORWARDER_MAX_LEN = 1024


def build_export_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE export table.

    Returns None if no export directory is present. Otherwise returns a
    dict per the module docstring contract. Never raises; decode failures
    produce tombstone entries in the `errors` and `truncations` lists.
    """
    placement = _locate_export_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    errors: List[str] = []
    truncations: List[str] = []

    # Read the 40-byte export directory header from raw bytes
    try:
        header_bytes = bytes(pe.get_data(rva, _EXPORT_DIRECTORY_SIZE))
    except Exception:
        return _empty_result(rva, size, errors=["header_read_failed"])

    if len(header_bytes) < _EXPORT_DIRECTORY_SIZE:
        truncations.append("export_directory_header")
        return _empty_result(rva, size,
                             errors=errors,
                             truncations=truncations)

    header = _decode_export_directory(header_bytes)
    if header is None:
        return _empty_result(rva, size, errors=["header_unpack_failed"])

    # Compute the directory's extent for forwarder detection (PE spec:
    # if an EAT entry's RVA points within the export directory, it's a
    # forwarder).
    dir_start = rva
    dir_end = rva + size

    # ---- Read EAT (Export Address Table) ----
    eat = _read_dword_array(
        pe,
        header["AddressOfFunctions"],
        header["NumberOfFunctions"],
        truncations,
        tag="eat",
    )

    # ---- Read ENPT (Export Name Pointer Table) ----
    enpt = _read_dword_array(
        pe,
        header["AddressOfNames"],
        header["NumberOfNames"],
        truncations,
        tag="enpt",
    )

    # ---- Read EOT (Export Ordinal Table) ----
    eot = _read_word_array(
        pe,
        header["AddressOfNameOrdinals"],
        header["NumberOfNames"],
        truncations,
        tag="eot",
    )

    # Build name pointer entries with resolved names
    name_pointers, name_by_index = _build_name_pointers(pe, enpt, eot, header)

    # Build function entries, joining EAT with name resolution
    functions = _build_functions(
        pe, eat, header, dir_start, dir_end, name_by_index
    )

    return {
        "rva": rva,
        "size": size,
        "header": header,
        "functions": functions,
        "name_pointers": name_pointers,
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_export_directory(pe) -> Optional[tuple]:
    """
    Return (rva, size) of the export data directory, or None if absent.
    """
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_EXPORT_DIRECTORY_INDEX]
        rva = int(data_dir.VirtualAddress)
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if rva == 0 or size == 0:
        return None

    return (rva, size)


def _empty_result(
    rva: int,
    size: int,
    *,
    errors: Optional[List[str]] = None,
    truncations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a minimal result dict for early-return cases."""
    return {
        "rva": rva,
        "size": size,
        "header": None,
        "functions": [],
        "name_pointers": [],
        "truncations": truncations or [],
        "errors": errors or [],
    }


# =================================================================
# Header decoder
# =================================================================

def _decode_export_directory(buf: bytes) -> Optional[Dict[str, int]]:
    """
    Unpack the 40-byte IMAGE_EXPORT_DIRECTORY structure.

    Field order per PE spec:
        DWORD Characteristics
        DWORD TimeDateStamp
        WORD  MajorVersion
        WORD  MinorVersion
        DWORD Name
        DWORD Base
        DWORD NumberOfFunctions
        DWORD NumberOfNames
        DWORD AddressOfFunctions
        DWORD AddressOfNames
        DWORD AddressOfNameOrdinals
    """
    try:
        unpacked = struct.unpack_from("<II HH IIIIIII", buf, 0)
    except struct.error:
        return None

    (characteristics, timedatestamp, major, minor,
     name_rva, base,
     num_functions, num_names,
     addr_functions, addr_names, addr_name_ordinals) = unpacked

    return {
        "Characteristics": characteristics,
        "TimeDateStamp": timedatestamp,
        "MajorVersion": major,
        "MinorVersion": minor,
        "Name": name_rva,
        "Base": base,
        "NumberOfFunctions": num_functions,
        "NumberOfNames": num_names,
        "AddressOfFunctions": addr_functions,
        "AddressOfNames": addr_names,
        "AddressOfNameOrdinals": addr_name_ordinals,
    }


# =================================================================
# Array readers
# =================================================================

def _read_dword_array(
    pe,
    rva: int,
    count: int,
    truncations: List[str],
    tag: str,
) -> List[Optional[int]]:
    """
    Read `count` little-endian DWORDs starting at `rva`. Returns a list of
    exactly `count` elements; positions where the read failed contain None.
    Appends a truncation tag if fewer bytes were available than declared.
    """
    if count == 0:
        return []
    if rva == 0:
        truncations.append(f"{tag}_rva_zero")
        return [None] * count

    byte_count = count * 4
    try:
        raw = bytes(pe.get_data(rva, byte_count))
    except Exception:
        truncations.append(f"{tag}_read_failed")
        return [None] * count

    if len(raw) < byte_count:
        truncations.append(f"{tag}_truncated")

    result: List[Optional[int]] = []
    for i in range(count):
        offset = i * 4
        if offset + 4 > len(raw):
            result.append(None)
        else:
            result.append(struct.unpack_from("<I", raw, offset)[0])
    return result


def _read_word_array(
    pe,
    rva: int,
    count: int,
    truncations: List[str],
    tag: str,
) -> List[Optional[int]]:
    """
    Read `count` little-endian WORDs starting at `rva`. Same semantics as
    _read_dword_array.
    """
    if count == 0:
        return []
    if rva == 0:
        truncations.append(f"{tag}_rva_zero")
        return [None] * count

    byte_count = count * 2
    try:
        raw = bytes(pe.get_data(rva, byte_count))
    except Exception:
        truncations.append(f"{tag}_read_failed")
        return [None] * count

    if len(raw) < byte_count:
        truncations.append(f"{tag}_truncated")

    result: List[Optional[int]] = []
    for i in range(count):
        offset = i * 2
        if offset + 2 > len(raw):
            result.append(None)
        else:
            result.append(struct.unpack_from("<H", raw, offset)[0])
    return result


# =================================================================
# Name pointer table
# =================================================================

def _build_name_pointers(
    pe,
    enpt: List[Optional[int]],
    eot: List[Optional[int]],
    header: Dict[str, int],
) -> tuple:
    """
    Build the name pointer entries and a side index mapping
    EAT-index -> name, used by _build_functions to enrich function entries.
    """
    entries: List[Dict[str, Any]] = []
    name_by_index: Dict[int, tuple] = {}

    num_names = header["NumberOfNames"]
    num_funcs = header["NumberOfFunctions"]

    for i in range(num_names):
        name_rva = enpt[i] if i < len(enpt) else None
        ordinal_index = eot[i] if i < len(eot) else None
        entry_errors: List[str] = []
        name: Optional[str] = None
        name_valid = False

        if name_rva is None:
            entry_errors.append("name_rva_missing")
        elif name_rva == 0:
            entry_errors.append("name_rva_zero")
        else:
            name, decode_error = _read_asciiz(pe, name_rva, _NAME_MAX_LEN)
            if decode_error:
                entry_errors.append(decode_error)
            else:
                name_valid = _is_valid_export_name(name)
                if not name_valid:
                    entry_errors.append("name_not_printable_ascii")

        # Cross-check the ordinal index against EAT bounds
        if ordinal_index is None:
            entry_errors.append("ordinal_index_missing")
        elif ordinal_index >= num_funcs:
            entry_errors.append("ordinal_index_out_of_range")
        elif name is not None and name_valid:
            # Record the resolved name against its EAT index for use by
            # _build_functions
            if ordinal_index in name_by_index:
                entry_errors.append("ordinal_index_duplicate")
            name_by_index[ordinal_index] = (name, name_rva)

        entries.append({
            "index": i,
            "name_rva": name_rva,
            "ordinal_index": ordinal_index,
            "name": name,
            "name_valid": name_valid,
            "errors": entry_errors,
        })

    return entries, name_by_index


# =================================================================
# Function entries
# =================================================================

def _build_functions(
    pe,
    eat: List[Optional[int]],
    header: Dict[str, int],
    dir_start: int,
    dir_end: int,
    name_by_index: Dict[int, tuple],
) -> List[Dict[str, Any]]:
    """
    Build the function entry list from the EAT, joining with name resolution
    and decoding forwarder strings where applicable.
    """
    entries: List[Dict[str, Any]] = []
    base = header["Base"]
    num_funcs = header["NumberOfFunctions"]

    for i in range(num_funcs):
        address_rva = eat[i] if i < len(eat) else None
        ordinal = base + i

        is_forwarder = False
        forwarder: Optional[str] = None
        forwarder_valid = False
        entry_errors: List[str] = []

        if address_rva is not None and address_rva != 0:
            # PE spec: an EAT entry RVA that points within the export
            # directory itself is a forwarder string pointer.
            if dir_start <= address_rva < dir_end:
                is_forwarder = True
                forwarder, fwd_error = _read_asciiz(
                    pe, address_rva, _FORWARDER_MAX_LEN
                )
                if fwd_error is not None:
                    entry_errors.append(fwd_error)
                if forwarder is not None:
                    forwarder_valid = bool(_FORWARDER_RE.match(forwarder))

        resolved = name_by_index.get(i)
        # Look up resolved name from name pointer table cross-reference
        name = resolved[0] if resolved else None
        name_rva = resolved[1] if resolved else None

        entries.append({
            "index": i,
            "ordinal": ordinal,
            "address_rva": address_rva,
            "is_forwarder": is_forwarder,
            "forwarder": forwarder,
            "forwarder_valid": forwarder_valid,
            "name": name,
            "name_rva": name_rva,
            "errors": entry_errors,
        })

    return entries


# =================================================================
# String reading
# =================================================================

def _read_asciiz(
    pe,
    rva: int,
    max_len: int,
) -> tuple:
    """
    Read a NUL-terminated ASCII string starting at `rva`. Returns
    (string, error_tag). On success, error_tag is None. On failure, string
    is None and error_tag describes the failure.

    Reads opportunistically: tries to read up to max_len bytes, accepts a
    short read as the available extent, and scans for the NUL terminator
    within whatever bytes came back.
    """
    if rva == 0:
        return None, "rva_zero"

    try:
        raw = bytes(pe.get_data(rva, max_len))
    except Exception:
        return None, "read_failed"

    if not raw:
        return None, "empty_read"

    nul_pos = raw.find(b"\x00")
    if nul_pos == -1:
        # No terminator found within max_len — treat as truncated
        return None, "unterminated"

    try:
        s = raw[:nul_pos].decode("ascii")
    except UnicodeDecodeError:
        # Fallback: decode with replacement, but flag the structural defect
        s = raw[:nul_pos].decode("ascii", errors="replace")
        return s, "non_ascii"

    return s, None


def _is_valid_export_name(s: str) -> bool:
    """
    PE export names should be printable ASCII identifiers. Conservative
    check: printable ASCII range only, no control chars, at least one char.
    """
    if not s:
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in s)
