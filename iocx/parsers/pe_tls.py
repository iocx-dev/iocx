# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE TLS directory.

Independent of pefile's DIRECTORY_ENTRY_TLS interpretation.
Pefile is used only to:
  - Locate the TLS directory (RVA, size)
  - Determine PE32 vs PE32+ via OPTIONAL_HEADER.Magic
  - Read OPTIONAL_HEADER.ImageBase (to convert VA -> RVA)
  - Resolve RVAs to file offsets via pe.get_data

IMPORTANT: the address fields in IMAGE_TLS_DIRECTORY are *virtual
addresses* (VAs), not RVAs. To read the callback array we convert
AddressOfCallBacks to an RVA by subtracting ImageBase.

IMAGE_TLS_DIRECTORY32 (24 bytes) / IMAGE_TLS_DIRECTORY64 (40 bytes):
    <ptr> StartAddressOfRawData   # VA
    <ptr> EndAddressOfRawData     # VA
    <ptr> AddressOfIndex          # VA
    <ptr> AddressOfCallBacks      # VA -> NULL-terminated array of VAs
    DWORD SizeOfZeroFill
    DWORD Characteristics
(<ptr> is 4 bytes on PE32, 8 bytes on PE32+)

Output contract:
    None - no TLS directory present (not an error)
    dict per the documented contract (see TlsStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_TLS = 9
_TLS_DIRECTORY_INDEX = 9

# OPTIONAL_HEADER.Magic values
_MAGIC_PE32 = 0x10B
_MAGIC_PE32_PLUS = 0x20B

# Hard cap on TLS callbacks to defend against looping / pathological
# arrays. Real binaries have a handful at most.
_MAX_CALLBACKS = 4096


def build_tls_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE TLS directory.

    Returns None if no TLS directory is present. Otherwise returns a dict
    per the module docstring contract. Never raises; decode failures
    produce tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_tls_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    is_64bit = _is_pe32_plus(pe)
    ptr_size = 8 if is_64bit else 4
    dir_size = 40 if is_64bit else 24
    image_base = _image_base(pe)

    truncations: List[str] = []
    errors: List[str] = []

    fields = _read_directory(pe, rva, dir_size, ptr_size, errors)
    if fields is None:
        return {
            "rva": rva,
            "size": size,
            "is_64bit": is_64bit,
            "image_base": image_base,
            "start_address_of_raw_data": None,
            "end_address_of_raw_data": None,
            "address_of_index": None,
            "address_of_callbacks": None,
            "size_of_zero_fill": None,
            "characteristics": None,
            "raw_data_size": None,
            "callbacks": [],
            "callback_count": 0,
            "truncations": truncations,
            "errors": errors,
        }

    (start_va, end_va, index_va, callbacks_va,
     size_of_zero_fill, characteristics) = fields

    raw_data_size = _raw_data_size(start_va, end_va, errors)

    callbacks = _read_callbacks(
        pe, callbacks_va, image_base, ptr_size, truncations, errors,
    )

    return {
        "rva": rva,
        "size": size,
        "is_64bit": is_64bit,
        "image_base": image_base,
        "start_address_of_raw_data": start_va,
        "end_address_of_raw_data": end_va,
        "address_of_index": index_va,
        "address_of_callbacks": callbacks_va,
        "size_of_zero_fill": size_of_zero_fill,
        "characteristics": characteristics,
        "raw_data_size": raw_data_size,
        "callbacks": callbacks,
        "callback_count": len(callbacks),
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_tls_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the TLS directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_TLS_DIRECTORY_INDEX]
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
        # Default to 32-bit if we can't tell. Conservative — narrower
        # pointers, lower risk of over-reading.
        return False


def _image_base(pe) -> Optional[int]:
    """Read OPTIONAL_HEADER.ImageBase, or None if unavailable."""
    try:
        return int(pe.OPTIONAL_HEADER.ImageBase)
    except (AttributeError, ValueError, TypeError):
        return None


# =================================================================
# Directory struct
# =================================================================

def _read_directory(
    pe,
    rva: int,
    dir_size: int,
    ptr_size: int,
    errors: List[str],
) -> Optional[Tuple[int, int, int, int, int, int]]:
    """Read and unpack the fixed IMAGE_TLS_DIRECTORY struct."""
    try:
        raw = bytes(pe.get_data(rva, dir_size))
    except Exception:
        errors.append("tls_directory_read_failed")
        return None

    if len(raw) < dir_size:
        errors.append("tls_directory_truncated")
        return None

    ptr_fmt = "Q" if ptr_size == 8 else "I"
    fmt = "<" + (ptr_fmt * 4) + "II"
    try:
        (start_va, end_va, index_va, callbacks_va,
         size_of_zero_fill, characteristics) = struct.unpack_from(fmt, raw, 0)
    except struct.error:
        errors.append("tls_directory_unpack_failed")
        return None

    return (start_va, end_va, index_va, callbacks_va,
            size_of_zero_fill, characteristics)


def _raw_data_size(
    start_va: int, end_va: int, errors: List[str],
) -> Optional[int]:
    """
    Compute EndAddressOfRawData - StartAddressOfRawData.

    A zero-length region (start == end) is valid and common. An end that
    precedes start is structurally invalid.
    """
    if end_va < start_va:
        errors.append("tls_raw_data_end_before_start")
        return None
    return end_va - start_va


# =================================================================
# Callback array
# =================================================================

def _read_callbacks(
    pe,
    callbacks_va: int,
    image_base: Optional[int],
    ptr_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[int]:
    """
    Read the NULL-terminated array of callback VAs.

    AddressOfCallBacks is a VA; convert to RVA by subtracting ImageBase.
    A zero AddressOfCallBacks means "no callbacks" (not an error). The
    read is capped to defend against looping / non-terminating arrays.
    """
    if callbacks_va == 0:
        return []

    if image_base is None:
        errors.append("tls_image_base_unavailable")
        return []

    callbacks_rva = callbacks_va - image_base
    if callbacks_rva < 0:
        errors.append("tls_callbacks_va_below_image_base")
        return []

    callbacks: List[int] = []
    pos = callbacks_rva
    fmt = "<Q" if ptr_size == 8 else "<I"

    for _ in range(_MAX_CALLBACKS):
        try:
            raw = bytes(pe.get_data(pos, ptr_size))
        except Exception:
            truncations.append("tls_callbacks_read_failed")
            break

        if len(raw) < ptr_size:
            truncations.append("tls_callbacks_truncated")
            break

        try:
            (value,) = struct.unpack_from(fmt, raw, 0)
        except struct.error:
            truncations.append("tls_callbacks_unpack_failed")
            break

        if value == 0:
            break  # NULL terminator

        callbacks.append(value)
        pos += ptr_size
    else:
        truncations.append("tls_callbacks_max_exceeded")

    return callbacks
