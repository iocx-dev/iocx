# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE import table.

Independent of pefile's DIRECTORY_ENTRY_IMPORT interpretation.
Pefile is used only to:
  - Locate the import directory (RVA, size)
  - Determine PE32 vs PE32+ via OPTIONAL_HEADER.Magic
  - Resolve RVAs to file offsets via pe.get_data

All structural fields are decoded from the raw 20-byte
IMAGE_IMPORT_DESCRIPTOR structure:

    DWORD OriginalFirstThunk    # RVA of the INT. MAY BE ZERO - see below.
    DWORD TimeDateStamp         # 0 = unbound; -1 = new-style bound
    DWORD ForwarderChain        # index of first forwarder, -1 = none
    DWORD Name                  # RVA of the ASCIIZ DLL name
    DWORD FirstThunk            # RVA of the IAT. Always required.

TWO DIVERGENCES FROM DELAY-LOAD:

1. `OriginalFirstThunk == 0` is LEGAL for standard imports, unlike the
   delay-load INT. Older linkers (Borland TLINK, some MS toolchains) emit
   only FirstThunk; on disk that array then holds INT-style thunks which the
   loader overwrites with addresses at load time. The parser therefore FALLS
   BACK to FirstThunk for name resolution and records which array it used in
   `thunk_source`. Flagging this as an anomaly would misreport a large
   fraction of legitimate binaries.

2. `TimeDateStamp` selects how FirstThunk should be read:
       0             - unbound; FirstThunk mirrors the INT on disk
       0xFFFFFFFF    - "new-style" bound; real timestamps live in
                       IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (index 11)
       anything else - "old-style" bound; FirstThunk holds RESOLVED
                       ADDRESSES on disk, not thunks
   When old-style bound AND OriginalFirstThunk is zero there is no readable
   name source at all, which is a genuine structural fact rather than a
   parse failure - tagged `names_unrecoverable_bound_no_int`.

The bound-import directory (index 11) is a separate structure and is NOT
parsed here.

Output contract:
    None - no import directory present (not an error)
    dict per the documented contract (see ImportStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_IMPORT = 1
_IMPORT_DIRECTORY_INDEX = 1
_DESCRIPTOR_SIZE = 20  # IMAGE_IMPORT_DESCRIPTOR is 20 bytes

# OPTIONAL_HEADER.Magic values
_MAGIC_PE32 = 0x10B
_MAGIC_PE32_PLUS = 0x20B

# TimeDateStamp sentinel for "new-style" bound imports.
_BOUND_NEW_STYLE = 0xFFFFFFFF

# DLL name length cap to defend against unterminated reads.
_DLL_NAME_MAX_LEN = 512
# Import-by-name length cap. Mangled C++ symbols legitimately run long, so
# this bounds the read only; printability is checked separately.
_IMPORT_NAME_MAX_LEN = 1024

# Hard limit on descriptors to defend against a directory claiming
# arbitrarily many. Real binaries rarely exceed a few hundred.
_MAX_DESCRIPTORS = 4096

# Hard limit on imports per descriptor, same rationale.
_MAX_IMPORTS_PER_DESCRIPTOR = 16384

# Printable-ASCII structural check, applied to both DLL names and import
# symbol names. Length is NOT constrained here - each caller applies its own
# limit where one is structurally meaningful, so a too-long name is reported
# distinctly from a non-printable one.
_PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7E]+$")

# NTFS filename component limit. An import DLL name is a filename, not a
# path, so 255 is the correct structural bound.
_DLL_NAME_MAX_CHARS = 255


def build_import_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE import table.

    Returns None if no import directory is present. Otherwise returns a dict
    per the module docstring contract. Never raises; decode failures produce
    tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_import_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    is_64bit = _is_pe32_plus(pe)
    thunk_size = 8 if is_64bit else 4
    truncations: List[str] = []
    errors: List[str] = []

    descriptors = _read_descriptors(
        pe, rva, size, thunk_size, truncations, errors,
    )

    return {
        "rva": rva,
        "size": size,
        "is_64bit": is_64bit,
        "descriptors": descriptors,
        "descriptor_count": len(descriptors),
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_import_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the import directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMPORT_DIRECTORY_INDEX]
        rva = int(data_dir.VirtualAddress)
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if rva == 0 or size == 0:
        return None

    return (rva, size)


def _is_pe32_plus(pe) -> bool:
    """Determine PE32+ (64-bit) by reading OPTIONAL_HEADER.Magic."""
    try:
        return int(pe.OPTIONAL_HEADER.Magic) == _MAGIC_PE32_PLUS
    except (AttributeError, ValueError, TypeError):
        # Default to 32-bit if we cannot tell. Conservative - narrower
        # thunks, lower risk of over-reading.
        return False


# =================================================================
# Descriptor array
# =================================================================

def _read_descriptors(
    pe,
    base_rva: int,
    declared_size: int,
    thunk_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[Dict[str, Any]]:
    """
    Walk the array of IMAGE_IMPORT_DESCRIPTOR structures.

    The array is terminated by an all-zero descriptor. We also stop at the
    declared directory size and enforce a hard count limit.
    """
    descriptors: List[Dict[str, Any]] = []
    pos = base_rva
    end = base_rva + declared_size

    for index in range(_MAX_DESCRIPTORS):
        if pos + _DESCRIPTOR_SIZE > end:
            # Reached the declared end without a zero terminator. Only
            # meaningful if we decoded at least one descriptor.
            if descriptors:
                truncations.append("import_descriptor_unterminated")
            break

        try:
            raw = bytes(pe.get_data(pos, _DESCRIPTOR_SIZE))
        except Exception:
            truncations.append("import_descriptor_read_failed")
            break

        if len(raw) < _DESCRIPTOR_SIZE:
            truncations.append("import_descriptor_truncated")
            break

        decoded = _decode_descriptor(raw, index)
        if decoded is None:  # pragma: no cover - guarded by the length check
            errors.append("descriptor_unpack_failed")
            break

        # Zero terminator ends the array and is not itself an entry.
        if _is_zero_descriptor(decoded):
            break

        _enrich_descriptor(pe, decoded, thunk_size, truncations)
        descriptors.append(decoded)
        pos += _DESCRIPTOR_SIZE
    else:
        truncations.append("import_descriptor_max_exceeded")

    return descriptors


def _decode_descriptor(buf: bytes, index: int) -> Optional[Dict[str, Any]]:
    """Unpack a 20-byte IMAGE_IMPORT_DESCRIPTOR."""
    try:
        (original_first_thunk, timestamp, forwarder_chain,
         name_rva, first_thunk) = struct.unpack_from("<IIIII", buf, 0)
    except struct.error:  # pragma: no cover - caller guarantees 20 bytes
        return None

    # Bound state. Note this is a property of the DESCRIPTOR, not of the
    # separate BOUND_IMPORT directory, which we do not parse.
    if timestamp == 0:
        bound_state = "unbound"
    elif timestamp == _BOUND_NEW_STYLE:
        bound_state = "bound_new_style"
    else:
        bound_state = "bound_old_style"

    return {
        "index": index,
        "original_first_thunk": original_first_thunk,
        "timestamp": timestamp,
        "forwarder_chain": forwarder_chain,
        "name_rva": name_rva,
        "first_thunk": first_thunk,
        "bound_state": bound_state,
        "dll_name": None,
        "dll_name_valid": False,
        # Which array the imports were actually read from. "int" is the
        # normal case; "iat_fallback" means OriginalFirstThunk was zero.
        "thunk_source": None,
        "imports": [],
        "errors": [],
    }


def _is_zero_descriptor(d: Dict[str, Any]) -> bool:
    """An all-zero descriptor signals end of array."""
    return (
        d["original_first_thunk"] == 0
        and d["timestamp"] == 0
        and d["forwarder_chain"] == 0
        and d["name_rva"] == 0
        and d["first_thunk"] == 0
    )


# =================================================================
# Per-descriptor enrichment
# =================================================================

def _enrich_descriptor(
    pe,
    descriptor: Dict[str, Any],
    thunk_size: int,
    truncations: List[str],
) -> None:
    """Read the DLL name and walk the name-source thunk array."""
    _read_dll_name(pe, descriptor)

    int_rva = descriptor["original_first_thunk"]
    iat_rva = descriptor["first_thunk"]
    bound_state = descriptor["bound_state"]

    # ---- Select the array to read names from ----
    #
    # Normal case: OriginalFirstThunk points at the INT.
    #
    # Fallback: OriginalFirstThunk == 0 is legal; FirstThunk then holds the
    # INT-style thunks on disk. This is NOT an anomaly.
    #
    # Exception: if the descriptor is old-style bound, FirstThunk holds
    # resolved ADDRESSES rather than thunks, so with no INT there is no
    # readable name source at all.
    if int_rva != 0:
        source_rva, source = int_rva, "int"
    elif iat_rva != 0:
        if bound_state == "bound_old_style":
            descriptor["errors"].append("names_unrecoverable_bound_no_int")
            return
        source_rva, source = iat_rva, "iat_fallback"
    else:
        # Neither array present - the descriptor names no imports at all.
        descriptor["errors"].append("no_thunk_array")
        return

    descriptor["thunk_source"] = source

    thunks = _read_thunk_array(
        pe, source_rva, thunk_size, source,
        descriptor["errors"], truncations,
    )

    high_bit = 1 << (thunk_size * 8 - 1)
    for i, value in enumerate(thunks):
        descriptor["imports"].append(
            _decode_import_entry(pe, i, value, high_bit)
        )


def _read_dll_name(pe, descriptor: Dict[str, Any]) -> None:
    """Read and structurally check the ASCIIZ DLL name."""
    name_rva = descriptor["name_rva"]
    if name_rva == 0:
        descriptor["errors"].append("dll_name_rva_zero")
        return

    name, err = _read_asciiz(pe, name_rva, _DLL_NAME_MAX_LEN)
    if err is not None:
        descriptor["errors"].append(err)
        return

    descriptor["dll_name"] = name
    # Three distinct structural faults, reported separately: an empty name, a
    # non-printable one, and one exceeding the filename limit are different
    # anomalies and a consumer triaging on "not_printable" should not be
    # shown a length violation.
    if name == "":
        descriptor["errors"].append("dll_name_empty")
    elif not _PRINTABLE_ASCII_RE.match(name):
        descriptor["errors"].append("dll_name_not_printable")
    elif len(name) > _DLL_NAME_MAX_CHARS:
        descriptor["errors"].append("dll_name_too_long")
    else:
        descriptor["dll_name_valid"] = True


def _decode_import_entry(
    pe,
    index: int,
    thunk_value: int,
    high_bit: int,
) -> Dict[str, Any]:
    """
    Build one ImportEntry from a thunk value.

    Thunk semantics:
      - High bit set: the low 16 bits are an ordinal.
      - High bit clear: the value is an RVA to IMAGE_IMPORT_BY_NAME.
    """
    errors: List[str] = []
    is_ordinal = False
    ordinal: Optional[int] = None
    hint: Optional[int] = None
    name: Optional[str] = None
    name_rva: Optional[int] = None
    name_valid = False

    if thunk_value & high_bit:
        is_ordinal = True
        # Ordinal is the low 16 bits per PE spec. Bits between 16 and the
        # high flag are discarded, matching the loader.
        ordinal = thunk_value & 0xFFFF
        if ordinal == 0:
            errors.append("ordinal_zero")
    else:
        name_rva = thunk_value
        hint, name, read_err = _read_import_by_name(pe, name_rva)
        if read_err is not None:
            errors.append(read_err)
        elif name is None:  # pragma: no cover - defensive
            errors.append("name_read_failed")
        else:
            # No length cap: _IMPORT_NAME_MAX_LEN already bounds the read,
            # and mangled C++ symbols legitimately exceed any smaller limit.
            if name == "":
                errors.append("name_empty")
            elif not _PRINTABLE_ASCII_RE.match(name):
                errors.append("name_not_printable")
            else:
                name_valid = True

    return {
        "index": index,
        "thunk_value": thunk_value,
        "is_ordinal": is_ordinal,
        "ordinal": ordinal,
        "hint": hint,
        "name": name,
        "name_rva": name_rva,
        "name_valid": name_valid,
        "errors": errors,
    }


# =================================================================
# Thunk array reader
# =================================================================

def _read_thunk_array(
    pe,
    rva: int,
    thunk_size: int,
    tag: str,
    descriptor_errors: List[str],
    truncations: List[str],
) -> List[int]:
    """
    Read a NULL-terminated array of thunks.

    Walks one thunk at a time until a zero terminator is found, the
    per-descriptor limit is hit, or the read fails.
    """
    thunks: List[int] = []
    pos = rva
    fmt = "<Q" if thunk_size == 8 else "<I"

    for _ in range(_MAX_IMPORTS_PER_DESCRIPTOR):
        try:
            raw = bytes(pe.get_data(pos, thunk_size))
        except Exception:
            truncations.append(f"{tag}_read_failed")
            break

        if len(raw) < thunk_size:
            truncations.append(f"{tag}_truncated")
            break

        try:
            (value,) = struct.unpack_from(fmt, raw, 0)
        except struct.error:  # pragma: no cover - guarded by length check
            truncations.append(f"{tag}_unpack_failed")
            break

        if value == 0:
            break  # NULL terminator

        thunks.append(value)
        pos += thunk_size
    else:
        truncations.append(f"{tag}_max_exceeded")

    return thunks


# =================================================================
# String reading
# =================================================================

def _read_asciiz(
    pe,
    rva: int,
    max_len: int,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Read a NUL-terminated ASCII string at `rva`.
    Returns (string, error_tag); error_tag is None on success.
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
        return None, "unterminated"

    try:
        return raw[:nul_pos].decode("ascii"), None
    except UnicodeDecodeError:
        return raw[:nul_pos].decode("ascii", errors="replace"), "non_ascii"


def _read_import_by_name(
    pe,
    rva: int,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Read IMAGE_IMPORT_BY_NAME:
        WORD Hint
        BYTE Name[]   (NUL-terminated ASCII)

    Returns (hint, name, error_tag).
    """
    if rva == 0:
        return None, None, "name_rva_zero"

    try:
        raw = bytes(pe.get_data(rva, _IMPORT_NAME_MAX_LEN))
    except Exception:
        return None, None, "name_read_failed"

    if len(raw) < 3:
        return None, None, "name_too_short"

    try:
        (hint,) = struct.unpack_from("<H", raw, 0)
    except struct.error:  # pragma: no cover - guarded by length check
        return None, None, "hint_unpack_failed"

    nul_pos = raw.find(b"\x00", 2)
    if nul_pos == -1:
        return hint, None, "name_unterminated"

    try:
        return hint, raw[2:nul_pos].decode("ascii"), None
    except UnicodeDecodeError:
        return hint, raw[2:nul_pos].decode("ascii", errors="replace"), "name_non_ascii"
