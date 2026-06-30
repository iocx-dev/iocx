# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE delay-load import table.

Independent of pefile's DIRECTORY_ENTRY_DELAY_IMPORT interpretation.
Pefile is used only to:
  - Locate the delay-load directory (RVA, size)
  - Determine PE32 vs PE32+ via OPTIONAL_HEADER.Magic
  - Resolve RVAs to file offsets via pe.get_data

All structural fields are decoded from the raw 32-byte
IMAGE_DELAY_IMPORT_DESCRIPTOR structure. The INT, IAT, and DLL name
strings are read raw.

Output contract:
    None - no delay-load directory present (not an error)
    dict per the documented contract (see DelayImportStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
_DELAY_IMPORT_DIRECTORY_INDEX = 13
_DESCRIPTOR_SIZE = 32  # IMAGE_DELAY_IMPORT_DESCRIPTOR is 32 bytes

# OPTIONAL_HEADER.Magic values
_MAGIC_PE32 = 0x10B
_MAGIC_PE32_PLUS = 0x20B

# DLL name length cap to defend against unterminated reads
_DLL_NAME_MAX_LEN = 512
# Import-by-name length cap
_IMPORT_NAME_MAX_LEN = 1024

# Hard limit on descriptors to defend against pathological inputs claiming
# arbitrarily many. Real binaries rarely have more than a few hundred.
_MAX_DESCRIPTORS = 4096

# Hard limit on imports per descriptor for the same reason
_MAX_IMPORTS_PER_DESCRIPTOR = 16384

# DLL name structural check: ASCII printable, typical filename charset.
# Conservative — accepts the common cases without trying to validate
# filesystem semantics.
_DLL_NAME_RE = re.compile(r"^[\x20-\x7E]{1,255}$")


def build_delay_import_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE delay-load import table.

    Returns None if no delay-load directory is present. Otherwise returns
    a dict per the module docstring contract. Never raises; decode
    failures produce tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_delay_import_directory(pe)
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
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_delay_import_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the delay-load directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_DELAY_IMPORT_DIRECTORY_INDEX]
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
        magic = int(pe.OPTIONAL_HEADER.Magic)
        return magic == _MAGIC_PE32_PLUS
    except (AttributeError, ValueError, TypeError):
        # Default to 32-bit if we can't tell. Conservative — produces
        # smaller thunks, lower risk of over-reading buffers.
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
    Walk the array of IMAGE_DELAY_IMPORT_DESCRIPTOR structures.

    The array is terminated by a zero descriptor (all 32 bytes zero).
    We also enforce a max descriptor count and stop at the declared
    directory size to defend against pathological inputs.
    """
    descriptors: List[Dict[str, Any]] = []
    pos = base_rva
    end = base_rva + declared_size

    # Read up to _MAX_DESCRIPTORS or until zero terminator or end
    for index in range(_MAX_DESCRIPTORS):
        if pos + _DESCRIPTOR_SIZE > end:
            # Declared size exceeded — could be truncation or just end
            # of the array without a zero terminator. We tag it only if
            # we haven't yet seen a zero terminator.
            if descriptors and not _is_zero_terminator(descriptors[-1]):
                truncations.append("delay_import_descriptor_unterminated")
            break

        try:
            raw = bytes(pe.get_data(pos, _DESCRIPTOR_SIZE))
        except Exception:
            truncations.append("delay_import_descriptor_read_failed")
            break

        if len(raw) < _DESCRIPTOR_SIZE:
            truncations.append("delay_import_descriptor_truncated")
            break

        decoded = _decode_descriptor(raw, index)
        if decoded is None:
            errors.append(f"descriptor_unpack_failed_at_{index}")
            break

        # Check for zero terminator BEFORE adding to results
        if _is_zero_descriptor(decoded):
            break

        # Read INT, IAT, and DLL name for this descriptor
        _enrich_descriptor(pe, decoded, thunk_size, truncations)
        descriptors.append(decoded)
        pos += _DESCRIPTOR_SIZE
    else:
        # Hit max without finding terminator
        truncations.append("delay_import_descriptor_max_exceeded")

    return descriptors


def _decode_descriptor(buf: bytes, index: int) -> Optional[Dict[str, Any]]:
    """Unpack a 32-byte IMAGE_DELAY_IMPORT_DESCRIPTOR."""
    try:
        unpacked = struct.unpack_from("<IIIIIIII", buf, 0)
    except struct.error:
        return None

    (attributes, dll_name_rva, module_handle_rva,
     iat_rva, int_rva, bound_iat_rva, unload_iat_rva,
     timestamp) = unpacked

    # Low bit of Attributes indicates v1 (modern RVA mode).
    # v0 binaries use raw VAs in the table fields, which would need
    # subtraction of ImageBase to convert to RVA. We capture the mode
    # but treat the RVAs as-is; the validator can flag v0 binaries.
    attributes_v1 = bool(attributes & 0x01)

    return {
        "index": index,
        "attributes": attributes,
        "attributes_v1": attributes_v1,
        "dll_name_rva": dll_name_rva,
        "dll_name": None,
        "dll_name_valid": False,
        "module_handle_rva": module_handle_rva,
        "iat_rva": iat_rva,
        "int_rva": int_rva,
        "bound_iat_rva": bound_iat_rva,
        "unload_iat_rva": unload_iat_rva,
        "timestamp": timestamp,
        "is_bound": bound_iat_rva != 0,
        "imports": [],
        "errors": [],
    }


def _is_zero_descriptor(d: Dict[str, Any]) -> bool:
    """A descriptor with all-zero fields signals end of array."""
    return (
        d["attributes"] == 0
        and d["dll_name_rva"] == 0
        and d["module_handle_rva"] == 0
        and d["iat_rva"] == 0
        and d["int_rva"] == 0
        and d["bound_iat_rva"] == 0
        and d["unload_iat_rva"] == 0
        and d["timestamp"] == 0
    )


def _is_zero_terminator(d: Dict[str, Any]) -> bool:
    """Convenience for the unterminated-array check."""
    return _is_zero_descriptor(d)


# =================================================================
# Per-descriptor enrichment
# =================================================================

def _enrich_descriptor(
    pe,
    descriptor: Dict[str, Any],
    thunk_size: int,
    truncations: List[str],
) -> None:
    """Read DLL name, INT/IAT thunks, and per-import name strings."""
    # ---- DLL name ----
    dll_name_rva = descriptor["dll_name_rva"]
    if dll_name_rva == 0:
        descriptor["errors"].append("dll_name_rva_zero")
    else:
        name, err = _read_asciiz(pe, dll_name_rva, _DLL_NAME_MAX_LEN)
        if err is not None:
            descriptor["errors"].append(err)
        else:
            descriptor["dll_name"] = name
            descriptor["dll_name_valid"] = bool(_DLL_NAME_RE.match(name))
            if not descriptor["dll_name_valid"]:
                descriptor["errors"].append("dll_name_not_printable")

    # ---- INT (Import Name Table) ----
    int_rva = descriptor["int_rva"]
    int_thunks = _read_thunk_array(
        pe, int_rva, thunk_size, "int",
        descriptor["errors"], truncations,
    )

    # ---- IAT (Import Address Table) ----
    iat_rva = descriptor["iat_rva"]
    iat_thunks = _read_thunk_array(
        pe, iat_rva, thunk_size, "iat",
        descriptor["errors"], truncations,
    )

    # ---- Cross-validate INT/IAT lengths ----
    if len(int_thunks) != len(iat_thunks):
        descriptor["errors"].append("int_iat_length_mismatch")

    # ---- Build per-import entries by joining INT and IAT ----
    max_len = max(len(int_thunks), len(iat_thunks))
    high_bit = 1 << (thunk_size * 8 - 1)

    for i in range(max_len):
        int_value = int_thunks[i] if i < len(int_thunks) else None
        iat_value = iat_thunks[i] if i < len(iat_thunks) else None
        entry = _decode_import_entry(
            pe, i, int_value, iat_value, high_bit, thunk_size,
        )
        descriptor["imports"].append(entry)


def _decode_import_entry(
    pe,
    index: int,
    int_value: Optional[int],
    iat_value: Optional[int],
    high_bit: int,
    thunk_size: int,
) -> Dict[str, Any]:
    """
    Build one DelayImportEntry from an INT/IAT pair.

    INT entry semantics:
      - High bit set: low bits are an ordinal value
      - High bit clear: value is an RVA to IMAGE_IMPORT_BY_NAME
    """
    errors: List[str] = []
    is_ordinal = False
    ordinal: Optional[int] = None
    hint: Optional[int] = None
    name: Optional[str] = None
    name_rva: Optional[int] = None
    name_valid = False

    if int_value is None:
        errors.append("int_entry_missing")
    elif int_value == 0:
        errors.append("int_entry_zero")
    elif int_value & high_bit:
        is_ordinal = True
        # Ordinal is the low 16 bits per PE spec
        ordinal = int_value & 0xFFFF
        if ordinal == 0:
            errors.append("ordinal_zero")
    else:
        name_rva = int_value
        # Read IMAGE_IMPORT_BY_NAME: WORD hint + ASCIIZ name
        hint, name, read_err = _read_import_by_name(pe, name_rva)
        if read_err is not None:
            errors.append(read_err)
        elif name is None:
            errors.append("name_read_failed")
        else:
            name_valid = bool(re.match(r"^[\x20-\x7E]{1,512}$", name))
            if not name_valid:
                errors.append("name_not_printable")

    return {
        "index": index,
        "is_ordinal": is_ordinal,
        "ordinal": ordinal,
        "hint": hint,
        "name": name,
        "name_rva": name_rva,
        "name_valid": name_valid,
        "iat_value": iat_value,
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
    Read a NULL-terminated array of thunks (INT or IAT).

    Walks one thunk at a time until either a zero terminator is found,
    the max-imports limit is hit, or the read fails.
    """
    if rva == 0:
        descriptor_errors.append(f"{tag}_rva_zero")
        return []

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
        except struct.error:
            truncations.append(f"{tag}_unpack_failed")
            break

        if value == 0:
            break  # NULL terminator
        thunks.append(value)
        pos += thunk_size
    else:
        # Hit max without finding terminator
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
    Read a NUL-terminated ASCII string at the given RVA.
    Returns (string, error_tag). On success, error_tag is None.
    """
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
        s = raw[:nul_pos].decode("ascii")
    except UnicodeDecodeError:
        s = raw[:nul_pos].decode("ascii", errors="replace")
        return s, "non_ascii"

    return s, None


def _read_import_by_name(
    pe,
    rva: int,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Read IMAGE_IMPORT_BY_NAME structure:
        WORD Hint
        BYTE Name[]    (NUL-terminated ASCII)

    Returns (hint, name, error_tag).
    """
    try:
        raw = bytes(pe.get_data(rva, _IMPORT_NAME_MAX_LEN))
    except Exception:
        return None, None, "name_read_failed"

    if len(raw) < 3:
        return None, None, "name_too_short"

    try:
        (hint,) = struct.unpack_from("<H", raw, 0)
    except struct.error:
        return None, None, "hint_unpack_failed"

    nul_pos = raw.find(b"\x00", 2)
    if nul_pos == -1:
        return hint, None, "name_unterminated"

    try:
        name = raw[2:nul_pos].decode("ascii")
    except UnicodeDecodeError:
        name = raw[2:nul_pos].decode("ascii", errors="replace")
        return hint, name, "name_non_ascii"

    return hint, name, None
