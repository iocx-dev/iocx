# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE certificate (Attribute
Certificate) table.

Independent of pefile's DIRECTORY_ENTRY_SECURITY interpretation.
Pefile is used only to:
  - Locate the security directory (file offset, size)
  - Provide the raw file bytes via pe.__data__
  - Provide section raw-data extents for the "outside the image" fact

IMPORTANT: For the security directory, DATA_DIRECTORY[4].VirtualAddress
is a *file offset*, NOT an RVA. The certificate table is appended to the
file and is not mapped into the image, so it must be read from the raw
file bytes, never resolved through pe.get_data.

Each entry is a WIN_CERTIFICATE:
    DWORD dwLength           # total length incl. this 8-byte header
    WORD  wRevision          # 0x0100 (1.0) or 0x0200 (2.0)
    WORD  wCertificateType   # WIN_CERT_TYPE_*
    BYTE  bCertificate[]     # opaque blob (not parsed here)

Entries are 8-byte (QWORD) aligned. We decode structure only; the
embedded PKCS#7 blob is deliberately left opaque (static, no crypto).

Output contract:
    None - no certificate directory present (not an error)
    dict per the documented contract (see CertificateStruct in
    iocx.schemas.internal_schema).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_SECURITY = 4
_SECURITY_DIRECTORY_INDEX = 4
_WIN_CERT_HEADER_SIZE = 8   # dwLength + wRevision + wCertificateType
_CERT_ALIGNMENT = 8         # entries are QWORD-aligned

# Hard cap on the number of certificate entries.
_MAX_CERTIFICATES = 1024

# WIN_CERT_REVISION_*
_REVISION_NAMES = {
    0x0100: "REVISION_1_0",
    0x0200: "REVISION_2_0",
}

# WIN_CERT_TYPE_*
_CERT_TYPE_NAMES = {
    0x0001: "X509",
    0x0002: "PKCS_SIGNED_DATA",
    0x0003: "RESERVED_1",
    0x0004: "TS_STACK_SIGNED",
}


def build_certificate_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE certificate table.

    Returns None if no security directory is present. Otherwise returns a
    dict per the module docstring contract. Never raises; decode failures
    produce tombstone entries in `errors` and `truncations`.
    """
    placement = _locate_security_directory(pe)
    if placement is None:
        return None

    offset, size = placement
    truncations: List[str] = []
    errors: List[str] = []

    data = _raw_file_bytes(pe)
    if data is None:
        errors.append("raw_file_unavailable")
        return {
            "offset": offset,
            "size": size,
            "file_size": None,
            "image_raw_end": None,
            "overlaps_image": None,
            "certificates": [],
            "certificate_count": 0,
            "truncations": truncations,
            "errors": errors,
        }

    file_size = len(data)
    image_raw_end = _image_raw_end(pe)
    # Structural fact only — the validator decides whether an overlap is a
    # defect. A certificate table that begins before the end of any
    # section's raw data overlaps mapped content on disk.
    overlaps_image = (
        image_raw_end is not None and offset < image_raw_end
    )

    certificates = _read_certificates(
        data, offset, size, file_size, truncations, errors,
    )

    return {
        "offset": offset,
        "size": size,
        "file_size": file_size,
        "image_raw_end": image_raw_end,
        "overlaps_image": overlaps_image,
        "certificates": certificates,
        "certificate_count": len(certificates),
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator
# =================================================================

def _locate_security_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (file_offset, size) of the security directory, or None."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_SECURITY_DIRECTORY_INDEX]
        offset = int(data_dir.VirtualAddress)  # file offset, not RVA
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if offset == 0 or size == 0:
        return None

    return (offset, size)


def _raw_file_bytes(pe) -> Optional[bytes]:
    """Return the raw file bytes backing the PE, or None if unavailable."""
    raw = getattr(pe, "__data__", None)
    if raw is None:
        return None
    try:
        return bytes(raw)
    except (TypeError, ValueError):
        return None


def _image_raw_end(pe) -> Optional[int]:
    """
    Largest (PointerToRawData + SizeOfRawData) across sections.

    This is the on-disk end of mapped content; the certificate table
    should begin at or after it. Returns None if sections are absent.
    """
    try:
        sections = pe.sections
    except AttributeError:
        return None
    if not sections:
        return None

    end = 0
    for section in sections:
        try:
            ptr = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
        except (AttributeError, ValueError, TypeError):
            continue
        if ptr and raw_size:
            end = max(end, ptr + raw_size)
    return end or None


# =================================================================
# Certificate array
# =================================================================

def _read_certificates(
    data: bytes,
    base_offset: int,
    declared_size: int,
    file_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[Dict[str, Any]]:
    """
    Walk the WIN_CERTIFICATE array within the declared directory window.

    Each entry's dwLength includes the 8-byte header; entries advance on
    an 8-byte alignment. A dwLength that fails to advance the cursor is
    fatal for the walk and tagged as malformed.
    """
    certificates: List[Dict[str, Any]] = []
    pos = base_offset
    end = base_offset + declared_size

    if base_offset > file_size:
        errors.append("certificate_offset_past_eof")
        return certificates

    if end > file_size:
        truncations.append("certificate_table_truncated")
        end = file_size

    for index in range(_MAX_CERTIFICATES):
        if pos >= end:
            break

        if pos + _WIN_CERT_HEADER_SIZE > end:
            truncations.append("certificate_header_truncated")
            break

        try:
            dw_length, revision, cert_type = struct.unpack_from(
                "<IHH", data, pos,
            )
        except struct.error:
            errors.append(f"certificate_header_unpack_failed_at_{index}")
            break

        cert = _decode_certificate(
            index, dw_length, revision, cert_type, pos, end, truncations,
        )
        certificates.append(cert)

        # A length that cannot advance the cursor is fatal for the walk.
        # The decoder has already tagged the entry, so we just stop.
        if dw_length < _WIN_CERT_HEADER_SIZE:
            break

        # Advance on 8-byte alignment.
        advance = _align_up(dw_length, _CERT_ALIGNMENT)
        pos += advance
    else:
        truncations.append("certificate_max_exceeded")

    return certificates


def _decode_certificate(
    index: int,
    dw_length: int,
    revision: int,
    cert_type: int,
    entry_offset: int,
    dir_end: int,
    truncations: List[str],
) -> Dict[str, Any]:
    """Decode a single WIN_CERTIFICATE header (blob left opaque)."""
    cert: Dict[str, Any] = {
        "index": index,
        "offset": entry_offset,
        "length": dw_length,
        "revision": revision,
        "revision_name": _REVISION_NAMES.get(revision),
        "cert_type": cert_type,
        "cert_type_name": _CERT_TYPE_NAMES.get(cert_type),
        "data_length": 0,
        "errors": [],
    }

    if dw_length < _WIN_CERT_HEADER_SIZE:
        cert["errors"].append("length_too_small")
        return cert

    data_length = dw_length - _WIN_CERT_HEADER_SIZE
    available = dir_end - (entry_offset + _WIN_CERT_HEADER_SIZE)
    if data_length > available:
        truncations.append("certificate_blob_truncated")
        data_length = max(0, available)

    cert["data_length"] = data_length

    if revision not in _REVISION_NAMES:
        cert["errors"].append("unknown_revision")
    if cert_type not in _CERT_TYPE_NAMES:
        cert["errors"].append("unknown_cert_type")

    return cert


# =================================================================
# Helpers
# =================================================================

def _align_up(value: int, alignment: int) -> int:
    """Round `value` up to the next multiple of `alignment`."""
    if alignment <= 0:
        return value
    remainder = value % alignment
    if remainder == 0:
        return value
    return value + (alignment - remainder)
