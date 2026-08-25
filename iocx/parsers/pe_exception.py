# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic structural extraction of the PE exception (.pdata) directory.

Independent of pefile's DIRECTORY_ENTRY_EXCEPTION interpretation.
Pefile is used only to:
  - Locate the exception directory (RVA, size)
  - Determine the target machine via FILE_HEADER.Machine
  - Resolve RVAs to file offsets via pe.get_data

The function table is a *counted* array (directory Size / entry stride), not a
zero-terminated one — unlike the delay-load descriptor array. Entry layout is
architecture-specific:

  AMD64 (x64):  12-byte RUNTIME_FUNCTION { BeginAddress, EndAddress,
                UnwindInfoAddress }, all 32-bit image-relative RVAs. The
                UnwindInfoAddress points at UNWIND_INFO in .xdata, which we
                decode for version/flags/prolog/code-count and chained-unwind.

  ARM64/ARMNT:  8-byte record { Function Start RVA, word1 }. The low 2 bits of
                word1 are a Flag: Flag==0 → the upper 30 bits (word1 & ~3) are
                an RVA to an .xdata record; Flag!=0 → word1 carries packed
                unwind data (no .xdata). There is NO EndAddress field, so
                end_rva is left None and the range/overlap checks in the
                validator naturally no-op for these entries. We do not decode
                .xdata / packed unwind semantics here (out of current scope).

  I386 / other: x86 carries no .pdata; any present directory on an
                unsupported machine is reported via arch="unsupported" and the
                function walk is skipped so no spurious per-entry codes fire.

All structural fields are decoded from the raw bytes. Never raises; decode
failures produce tombstone tags in per-entry `errors`, per-unwind `errors`,
and the table-level `truncations` / `errors` lists.

Output contract (consumed by validators.exception_table.validate_exception_table
and documented as ExceptionStruct in iocx.schemas.internal_schema):

    None - no exception directory present (not an error)
    {
      "rva": int, "size": int,
      "machine": Optional[int],       # IMAGE_FILE_MACHINE_*
      "arch": str,                    # "amd64" | "arm64" | "arm" | "unsupported"
      "entry_size": int,              # 12 (amd64) | 8 (arm) | 0 (unsupported)
      "errors": List[str],            # top-level decode tags
      "truncations": List[str],       # per-table truncation tags
      "functions": List[dict],        # see _decode_* below
    }
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
_EXCEPTION_DIRECTORY_INDEX = 3

# Entry strides.
_AMD64_ENTRY_SIZE = 12  # RUNTIME_FUNCTION: 3 x DWORD
_ARM_ENTRY_SIZE = 8     # ARM(64) .pdata record: 2 x DWORD

# IMAGE_FILE_MACHINE_* — only the values we need to route on.
_MACHINE_I386 = 0x014C
_MACHINE_AMD64 = 0x8664
_MACHINE_IA64 = 0x0200
_MACHINE_ARM = 0x01C0
_MACHINE_ARMNT = 0x01C4      # ARM Thumb-2 (Windows on ARM 32-bit)
_MACHINE_ARM64 = 0xAA64
_MACHINE_ARM64EC = 0xA641    # ARM64EC — uses the ARM64 .pdata table format

# UNWIND_INFO (AMD64) constants.
_DWORD = 4
_VALID_UNWIND_VERSIONS = (1, 2, 3)
_UNW_FLAG_CHAININFO = 0x04
_UNW_FLAG_KNOWN_MASK = 0x0F  # EHANDLER|UHANDLER|CHAININFO|LARGE(V3)
_UNWIND_HEADER_SIZE = 4
_RUNTIME_FUNCTION_SIZE = 12  # trailing chained RUNTIME_FUNCTION

# ARM word1 flag mask (low 2 bits) and the xdata-RVA mask (upper 30 bits).
_ARM_FLAG_MASK = 0x3
_ARM_XDATA_RVA_MASK = ~0x3 & 0xFFFFFFFF

# Hard limit on function-table entries to defend against a bogus directory
# Size claiming an absurd count. Real .pdata tables are large but bounded;
# 2**20 entries (~12 MiB of .pdata on x64) is already far beyond real images.
_MAX_FUNCTIONS = 1 << 20


def build_exception_structure(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and structurally decode the PE exception (.pdata) directory.

    Returns None if no exception directory is present. Otherwise returns a
    dict per the module docstring contract. Never raises; decode failures
    produce tombstone entries in `errors` / `truncations` and per-entry tags.
    """
    placement = _locate_exception_directory(pe)
    if placement is None:
        return None

    rva, size = placement
    machine = _read_machine(pe)
    arch = _classify_arch(machine)
    entry_size = _entry_size_for_arch(arch)

    truncations: List[str] = []
    errors: List[str] = []

    if arch == "unsupported" or entry_size == 0:
        # Directory present on a machine we don't deep-parse. Report the
        # placement so the validator can raise EXCEPTION_UNSUPPORTED_MACHINE;
        # emit no function entries.
        return {
            "rva": rva,
            "size": size,
            "machine": machine,
            "arch": arch,
            "entry_size": entry_size,
            "functions": [],
            "truncations": truncations,
            "errors": errors,
        }

    functions = _read_function_table(
        pe, rva, size, arch, entry_size, truncations, errors,
    )

    return {
        "rva": rva,
        "size": size,
        "machine": machine,
        "arch": arch,
        "entry_size": entry_size,
        "functions": functions,
        "truncations": truncations,
        "errors": errors,
    }


# =================================================================
# Locator / machine routing
# =================================================================

def _locate_exception_directory(pe) -> Optional[Tuple[int, int]]:
    """Return (rva, size) of the exception directory, or None if absent."""
    try:
        data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_EXCEPTION_DIRECTORY_INDEX]
        rva = int(data_dir.VirtualAddress)
        size = int(data_dir.Size)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    if rva == 0 or size == 0:
        return None

    return (rva, size)


def _read_machine(pe) -> Optional[int]:
    """Read FILE_HEADER.Machine, or None if unavailable."""
    try:
        return int(pe.FILE_HEADER.Machine)
    except (AttributeError, ValueError, TypeError):
        return None


def _classify_arch(machine: Optional[int]) -> str:
    """
    Map a machine type to a deep-parse architecture class.

    amd64 → 12-byte RUNTIME_FUNCTION with UNWIND_INFO.
    arm64/arm → 8-byte record (packed or .xdata pointer).
    unsupported → x86, IA-64, unknown, or unreadable.
    """
    if machine == _MACHINE_AMD64:
        return "amd64"
    if machine in (_MACHINE_ARM64, _MACHINE_ARM64EC):
        return "arm64"
    if machine in (_MACHINE_ARM, _MACHINE_ARMNT):
        return "arm"
    return "unsupported"


def _entry_size_for_arch(arch: str) -> int:
    """Per-entry stride in bytes for a given arch class (0 = unsupported)."""
    if arch == "amd64":
        return _AMD64_ENTRY_SIZE
    if arch in ("arm64", "arm"):
        return _ARM_ENTRY_SIZE
    return 0


# =================================================================
# Function-table walk
# =================================================================

def _read_function_table(
    pe,
    base_rva: int,
    declared_size: int,
    arch: str,
    entry_size: int,
    truncations: List[str],
    errors: List[str],
) -> List[Dict[str, Any]]:
    """
    Walk the counted array of function-table entries.

    Unlike the delay-import descriptor array, .pdata has no zero terminator:
    the entry count is declared_size // entry_size. We clamp to _MAX_FUNCTIONS
    and note when the declared size isn't a whole multiple of the stride (a
    ragged tail) — the directory-level validator also flags the size, but the
    parser records the truncation so a partial trailing entry never gets
    half-decoded.
    """
    functions: List[Dict[str, Any]] = []

    count = declared_size // entry_size
    remainder = declared_size % entry_size
    if remainder != 0:
        truncations.append("exception_table_ragged_tail")

    if count > _MAX_FUNCTIONS:
        truncations.append("exception_table_max_exceeded")
        count = _MAX_FUNCTIONS

    pos = base_rva
    for index in range(count):
        try:
            raw = bytes(pe.get_data(pos, entry_size))
        except Exception:
            truncations.append("exception_entry_read_failed")
            break

        if len(raw) < entry_size:
            truncations.append("exception_entry_truncated")
            break

        if arch == "amd64":
            entry = _decode_amd64_entry(pe, raw, index)
        else:  # arm64 / arm
            entry = _decode_arm_entry(raw, index, arch)

        functions.append(entry)
        pos += entry_size

    return functions


# =================================================================
# AMD64 entry + UNWIND_INFO
# =================================================================

def _decode_amd64_entry(pe, buf: bytes, index: int) -> Dict[str, Any]:
    """
    Decode one 12-byte RUNTIME_FUNCTION and its referenced UNWIND_INFO.

    Emits per-entry error tags consumed by the validator's
    _ENTRY_ERROR_PRIORITY (begin_rva_zero / end_rva_zero / unwind_rva_zero /
    entry_unpack_failed).
    """
    errors: List[str] = []
    try:
        begin_rva, end_rva, unwind_info_rva = struct.unpack_from("<III", buf, 0)
    except struct.error:
        return {
            "index": index,
            "begin_rva": None,
            "end_rva": None,
            "unwind_info_rva": None,
            "unwind": None,
            "errors": ["entry_unpack_failed"],
        }

    if begin_rva == 0:
        errors.append("begin_rva_zero")
    if end_rva == 0:
        errors.append("end_rva_zero")
    if unwind_info_rva == 0:
        errors.append("unwind_rva_zero")

    unwind = None
    if unwind_info_rva != 0:
        unwind = _decode_unwind_info(pe, unwind_info_rva)

    return {
        "index": index,
        "begin_rva": begin_rva,
        "end_rva": end_rva,
        "unwind_info_rva": unwind_info_rva,
        "unwind": unwind,
        "errors": errors,
    }


def _decode_unwind_info(pe, rva: int) -> Dict[str, Any]:
    """
    Decode the 4-byte UNWIND_INFO header (+ chained RUNTIME_FUNCTION if
    UNW_FLAG_CHAININFO is set).

    Header byte 0: bits[2:0] Version, bits[7:3] Flags.
    Header byte 1: SizeOfProlog. Byte 2: CountOfUnwindCodes.
    Byte 3: FrameRegister (low nibble) + scaled offset (high nibble).

    Full decode is defined for V1/V2. V3 (APX preview) reuses this header
    layout for Version/Flags but repacks the trailing payload differently, so
    we surface Version/Flags and stop there rather than mis-decode the chain —
    an honest "recognised, not deeply parsed" outcome. Emits tags consumed by
    the validator's _UNWIND_ERROR_PRIORITY.
    """
    errors: List[str] = []

    try:
        header = bytes(pe.get_data(rva, _UNWIND_HEADER_SIZE))
    except Exception:
        return _unwind_result(errors=["unwind_read_failed"])

    if len(header) < _UNWIND_HEADER_SIZE:
        return _unwind_result(errors=["unwind_truncated"])

    try:
        b0, size_of_prolog, count_of_codes, _frame = struct.unpack_from(
            "<BBBB", header, 0
        )
    except struct.error:
        return _unwind_result(errors=["unwind_unpack_failed"])

    version = b0 & 0x07
    flags = (b0 >> 3) & 0x1F

    if version not in _VALID_UNWIND_VERSIONS:
        errors.append("unwind_version_invalid")
    if (flags & ~_UNW_FLAG_KNOWN_MASK) != 0:
        errors.append("unwind_flags_reserved_bits")

    is_chained = False
    chained_rva: Optional[int] = None

    # Chain resolution is only reliable for the classic V1/V2 payload layout.
    if version in (1, 2) and (flags & _UNW_FLAG_CHAININFO):
        is_chained = True
        # Unwind codes are USHORT[]; the array is padded to an even count.
        padded_codes = (count_of_codes + 1) & ~1
        chain_off = _UNWIND_HEADER_SIZE + padded_codes * 2
        try:
            rf = bytes(pe.get_data(rva + chain_off, _RUNTIME_FUNCTION_SIZE))
        except Exception:
            errors.append("unwind_codes_truncated")
            rf = b""
        if len(rf) < _RUNTIME_FUNCTION_SIZE:
            if "unwind_codes_truncated" not in errors:
                errors.append("unwind_codes_truncated")
        else:
            # Trailing structure is a RUNTIME_FUNCTION whose UnwindInfoAddress
            # points at the *primary* fragment's UNWIND_INFO.
            try:
                _cb, _ce, chained_rva = struct.unpack_from("<III", rf, 0)
            except struct.error:
                errors.append("unwind_unpack_failed")

    return _unwind_result(
        version=version,
        flags=flags,
        size_of_prolog=size_of_prolog,
        count_of_codes=count_of_codes,
        is_chained=is_chained,
        chained_rva=chained_rva,
        errors=errors,
    )


def _unwind_result(
    version: Optional[int] = None,
    flags: Optional[int] = None,
    size_of_prolog: Optional[int] = None,
    count_of_codes: Optional[int] = None,
    is_chained: bool = False,
    chained_rva: Optional[int] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build the unwind sub-dict with a stable key set."""
    return {
        "version": version,
        "flags": flags,
        "size_of_prolog": size_of_prolog,
        "count_of_codes": count_of_codes,
        "is_chained": is_chained,
        "chained_rva": chained_rva,
        "errors": errors or [],
    }


# =================================================================
# ARM / ARM64 entry
# =================================================================

def _decode_arm_entry(buf: bytes, index: int, arch: str) -> Dict[str, Any]:
    """
    Decode one 8-byte ARM(64) .pdata record.

    word0 = Function Start RVA. word1 low 2 bits = Flag:
      Flag == 0 → (word1 & ~3) is an RVA to an .xdata record (unpacked).
      Flag != 0 → word1 is packed unwind data (no .xdata pointer).

    There is no EndAddress, so end_rva is None (the validator's range/overlap
    checks require both endpoints and therefore skip these entries). We do not
    decode .xdata / packed unwind bodies here; unwind is left None so only the
    structural table checks (bounds, sortedness, alignment) apply.
    """
    errors: List[str] = []
    try:
        begin_rva, word1 = struct.unpack_from("<II", buf, 0)
    except struct.error:
        return {
            "index": index,
            "begin_rva": None,
            "end_rva": None,
            "unwind_info_rva": None,
            "unwind": None,
            "is_packed": None,
            "errors": ["entry_unpack_failed"],
        }

    if begin_rva == 0:
        errors.append("begin_rva_zero")

    flag = word1 & _ARM_FLAG_MASK
    is_packed = flag != 0
    unwind_info_rva: Optional[int] = None
    if is_packed:
        # Packed unwind — no .xdata pointer to bounds-check.
        unwind_info_rva = None
    else:
        unwind_info_rva = word1 & _ARM_XDATA_RVA_MASK
        if unwind_info_rva == 0:
            errors.append("unwind_rva_zero")

    return {
        "index": index,
        "begin_rva": begin_rva,
        "end_rva": None,           # ARM(64) .pdata carries no EndAddress
        "unwind_info_rva": unwind_info_rva,
        "unwind": None,            # .xdata / packed body not decoded here
        "is_packed": is_packed,
        "packed_data": word1 if is_packed else None,
        "errors": errors,
    }
