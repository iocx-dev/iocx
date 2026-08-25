# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the exception (.pdata) directory structure — the deep semantic
counterpart to the generic RVA/placement checks in ``rva_graph``.

``rva_graph`` already treats IMAGE_DIRECTORY_ENTRY_EXCEPTION like any other
data directory (bounds, section mapping, overlap). This validator owns the
*semantic* truth of that directory: the sorted function table of
RUNTIME_FUNCTION entries and the UNWIND_INFO structures they reference.

Absence of an exception directory is NOT a structural defect — most 32-bit
(x86 / I386) images carry no .pdata at all (their SEH is stack-based), and a
64-bit image may legitimately omit it. We only emit codes when the directory
is present and structurally malformed.

Scope / grounding
-----------------
Deep parsing here is defined for table-based exception handling only:
  * AMD64 (x64):  array of 12-byte RUNTIME_FUNCTION entries, DWORD-aligned,
                  each { BeginAddress, EndAddress, UnwindInfoAddress } as
                  32-bit image-relative RVAs, SORTED ascending by
                  BeginAddress, referencing UNWIND_INFO in .xdata.
  * ARM64 / ARM:  also table-based (ARM_RUNTIME_FUNCTION, packed/unpacked
                  unwind). Structural table checks below apply; UNWIND_INFO
                  version/flag checks are AMD64-specific and are skipped.
Any other machine (notably I386) is reported once as unsupported-for-deep-parse
and the semantic walk is skipped — we do not manufacture false positives on
directories we cannot interpret.

Facts grounded against Microsoft's x64 exception-handling documentation and
the PE/COFF spec:
  - RUNTIME_FUNCTION is 12 bytes and must be DWORD aligned; all three fields
    are 32-bit image-relative RVAs. Entries are sorted ascending by
    BeginAddress and stored in .pdata of a PE32+ image.
  - EndAddress is the RVA of the first byte *past* the function, so a
    well-formed entry has BeginAddress < EndAddress.
  - UNWIND_INFO must be DWORD aligned; Version is 1 (V1/V2) or 3 (APX / V3
    preview). Flags are a mask of UNW_FLAG_EHANDLER(0x1), UNW_FLAG_UHANDLER
    (0x2), UNW_FLAG_CHAININFO(0x4), plus UNW_FLAG_LARGE(0x8) in V3.

Determinism
-----------
Every heuristic is a pure function of the parsed structure. Emission order is
fixed: directory-level checks, then a single ascending pass over the function
table (index order), then per-entry unwind checks. Per-entry pathologies are
collapsed to a single first-matching reason via ``_first_matching`` over a
fixed priority list. No set iteration governs what or when we emit. Same file
in → same StructuralIssue sequence out.

Reason codes emitted:
  EXCEPTION_DIRECTORY_INVALID_HEADER      top-level decode failure
  EXCEPTION_DIRECTORY_OUT_OF_BOUNDS       directory rva+size exceeds SizeOfImage
  EXCEPTION_DIRECTORY_UNALIGNED           directory rva not DWORD-aligned
  EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE   size not a multiple of entry stride
  EXCEPTION_TABLE_TRUNCATED               parser truncation tag(s)
  EXCEPTION_UNSUPPORTED_MACHINE           present but arch not deep-parseable
  EXCEPTION_ENTRY_INVALID                 per-entry parser error (priority-resolved)
  EXCEPTION_FUNCTION_RANGE_INVALID        begin >= end (empty/inverted range)
  EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS    begin/end/unwind RVA outside image
  EXCEPTION_ENTRIES_NOT_SORTED            BeginAddress not ascending (loader-visible)
  EXCEPTION_FUNCTION_OVERLAP              adjacent function ranges overlap
  EXCEPTION_UNWIND_INFO_UNALIGNED         UnwindInfoAddress not DWORD-aligned
  EXCEPTION_UNWIND_INFO_INVALID           unwind decode/version/flags anomaly (priority-resolved)
  EXCEPTION_UNWIND_CHAIN_INVALID          chained-unwind target invalid / cycle / depth

Parser contract (metadata["exception_struct"], populated by parser_exception):
  {
    "rva": int, "size": int,            # directory VirtualAddress / Size
    "machine": Optional[int],           # IMAGE_FILE_MACHINE_*
    "arch": str,                        # "amd64" | "arm64" | "arm" | "unsupported"
    "entry_size": int,                  # 12 for amd64
    "errors": List[str],                # top-level decode tags
    "truncations": List[str],           # per-table truncation tags
    "functions": [
      {
        "index": int,
        "begin_rva": Optional[int],
        "end_rva": Optional[int],
        "unwind_info_rva": Optional[int],   # amd64
        "errors": List[str],                # per-entry parser tags
        "unwind": {                         # amd64 only, optional
          "version": Optional[int],
          "flags": Optional[int],
          "size_of_prolog": Optional[int],
          "count_of_codes": Optional[int],
          "is_chained": bool,
          "chained_rva": Optional[int],
          "errors": List[str],              # per-unwind parser tags
        } | None,
      }, ...
    ],
  }
"""

from typing import Any, Dict, List, Optional

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# Architectures for which the RUNTIME_FUNCTION table walk is defined. x86
# (I386) carries no .pdata, so a present directory there is reported once as
# unsupported rather than semantically walked.
_TABLE_ARCHS = ("amd64", "arm64", "arm")

# AMD64 RUNTIME_FUNCTION stride and required alignment (DWORD).
_AMD64_ENTRY_SIZE = 12
_DWORD = 4

# Valid UNWIND_INFO version numbers: 1 (V1), 2 (V2), 3 (APX / V3 preview).
_VALID_UNWIND_VERSIONS = (1, 2, 3)

# Known UNW_FLAG bits: EHANDLER(0x1) | UHANDLER(0x2) | CHAININFO(0x4) |
# LARGE(0x8, V3). Any bit outside this mask is a reserved-bit anomaly.
_UNW_FLAG_KNOWN_MASK = 0x0F
_UNW_FLAG_CHAININFO = 0x04

# Guard against pathological / hostile chain graphs during the chain walk.
_MAX_CHAIN_DEPTH = 32


# Priority-resolved sub-reasons for per-entry table pathologies.
# First-matching wins for deterministic emission.
_ENTRY_ERROR_PRIORITY = [
    "entry_truncated",
    "entry_read_failed",
    "entry_unpack_failed",
    "begin_rva_zero",
    "end_rva_zero",
    "unwind_rva_zero",
]

_UNWIND_ERROR_PRIORITY = [
    "unwind_read_failed",
    "unwind_truncated",
    "unwind_unpack_failed",
    "unwind_version_invalid",
    "unwind_flags_reserved_bits",
    "unwind_codes_truncated",
]


@depends_on("internal", "analysis")
def validate_exception_table(metadata: InternalMetadata,
                             analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    ex = metadata.get("exception_struct")
    if ex is None:
        return issues  # no exception directory — not a defect

    size_of_image = analysis.get("size_of_image")

    # ---- Top-level decode failures short-circuit ----
    if ex.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_DIRECTORY_INVALID_HEADER,
            details={"reason": "top_level_decode",
                     "errors": list(ex["errors"])},
        ))
        return issues

    _validate_directory(ex, size_of_image, issues)
    _validate_truncations(ex, issues)

    # ---- Architecture gate ----
    # Deep table/unwind semantics are only defined for table-based archs.
    # Report once and stop rather than emit spurious per-entry noise.
    arch = ex.get("arch")
    if arch not in _TABLE_ARCHS:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_UNSUPPORTED_MACHINE,
            details={"arch": arch, "machine": ex.get("machine")},
        ))
        return issues

    _validate_function_table(ex, size_of_image, issues)
    return issues


# =================================================================
# Directory-level validation
# =================================================================

def _validate_directory(ex: Dict[str, Any],
                        size_of_image: Optional[int],
                        issues: List[StructuralIssue]) -> None:
    """
    Directory placement, alignment, and stride consistency.

    RUNTIME_FUNCTION entries must be DWORD aligned, so the directory RVA
    itself must be DWORD aligned, and Size must be a whole multiple of the
    per-entry stride (12 bytes on amd64).
    """
    rva = ex.get("rva")
    size = ex.get("size") or 0
    entry_size = ex.get("entry_size") or _AMD64_ENTRY_SIZE

    if rva is None:
        return

    # Placement within the mapped image. Mirrors the delay-import placement
    # check; rva_graph owns the generic version but we assert the semantic
    # invariant locally so this validator stands alone.
    if size_of_image is not None and rva + size > size_of_image:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_DIRECTORY_OUT_OF_BOUNDS,
            details={"rva": rva, "size": size,
                     "size_of_image": size_of_image},
        ))

    if rva % _DWORD != 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_DIRECTORY_UNALIGNED,
            details={"rva": rva, "alignment": _DWORD},
        ))

    if entry_size > 0 and size % entry_size != 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE,
            details={"size": size, "entry_size": entry_size,
                     "remainder": size % entry_size},
        ))


def _validate_truncations(ex: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """
    Map parser truncation tags to a single reason code with structured
    details. One issue per truncated table so the consumer sees one issue
    per truncation.
    """
    for tag in ex.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_TABLE_TRUNCATED,
            details={"table": tag},
        ))


# =================================================================
# Function-table validation (the semantic core)
# =================================================================

def _validate_function_table(ex: Dict[str, Any],
                             size_of_image: Optional[int],
                             issues: List[StructuralIssue]) -> None:
    """
    Single ascending pass over the RUNTIME_FUNCTION array.

    Per entry we check, in fixed order:
      1. parser error tags               → EXCEPTION_ENTRY_INVALID
      2. begin/end/unwind RVA bounds     → EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS
      3. range validity (begin < end)    → EXCEPTION_FUNCTION_RANGE_INVALID
      4. sortedness vs. previous begin   → EXCEPTION_ENTRIES_NOT_SORTED
      5. overlap vs. previous end        → EXCEPTION_FUNCTION_OVERLAP
      6. unwind alignment + semantics    → EXCEPTION_UNWIND_INFO_* codes

    Sortedness (4) is the loader-visible invariant: ntdll locates a function's
    unwind data by binary search over this table, so an out-of-order entry
    means a real function silently "loses" its exception/unwind data at
    runtime even though every byte is present on disk.
    """
    functions = ex.get("functions", []) or []

    prev_begin: Optional[int] = None
    prev_end: Optional[int] = None

    for entry in functions:
        index = entry.get("index")

        # ---- 1. Parser-level per-entry errors (priority-resolved) ----
        entry_errors = entry.get("errors", []) or []
        entry_reason = _first_matching(entry_errors, _ENTRY_ERROR_PRIORITY)
        if entry_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_ENTRY_INVALID,
                details={"index": index, "reason": entry_reason},
            ))
            # A structurally unreadable entry can't feed the cross-entry
            # invariants below; skip it but keep walking the table.
            continue

        begin = entry.get("begin_rva")
        end = entry.get("end_rva")
        unwind_rva = entry.get("unwind_info_rva")

        # ---- 2. RVA bounds ----
        oob_fields = _out_of_bounds_fields(begin, end, unwind_rva,
                                           size_of_image)
        if oob_fields:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS,
                details={"index": index,
                         "begin_rva": begin, "end_rva": end,
                         "unwind_info_rva": unwind_rva,
                         "fields": oob_fields,
                         "size_of_image": size_of_image},
            ))

        # ---- 3. Range validity ----
        if isinstance(begin, int) and isinstance(end, int) and begin >= end:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_FUNCTION_RANGE_INVALID,
                details={"index": index, "begin_rva": begin, "end_rva": end,
                         "empty": begin == end},
            ))

        # ---- 4. Sortedness (ascending BeginAddress) ----
        if isinstance(begin, int) and prev_begin is not None \
                and begin < prev_begin:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_ENTRIES_NOT_SORTED,
                details={"index": index, "begin_rva": begin,
                         "prev_begin_rva": prev_begin},
            ))

        # ---- 5. Overlap with previous function range ----
        # Only meaningful when this entry starts at/after the previous one
        # (i.e. the table is locally sorted); an unsorted pair is already
        # flagged above and we don't double-count it as an overlap.
        if isinstance(begin, int) and prev_end is not None \
                and prev_begin is not None and begin >= prev_begin \
                and begin < prev_end:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_FUNCTION_OVERLAP,
                details={"index": index, "begin_rva": begin,
                         "prev_end_rva": prev_end},
            ))

        # ---- 6. Unwind-info semantics (amd64) ----
        _validate_unwind_info(index, entry.get("unwind"), unwind_rva,
                              size_of_image, issues)

        # Advance the ascending cursor only on sane, sorted begins so a single
        # wild entry doesn't poison every subsequent comparison.
        if isinstance(begin, int) and (prev_begin is None or begin >= prev_begin):
            prev_begin = begin
            if isinstance(end, int):
                prev_end = end


def _validate_unwind_info(index: Optional[int],
                          unwind: Optional[Dict[str, Any]],
                          unwind_rva: Optional[int],
                          size_of_image: Optional[int],
                          issues: List[StructuralIssue]) -> None:
    """
    UNWIND_INFO alignment, decode, version, flags, and chain sanity.

    AMD64-specific. On ARM/ARM64 the parser omits ``unwind`` (packed unwind
    has no comparable version/flags byte), so these checks are skipped.
    """
    # Alignment is checkable from the RVA alone, independent of decode.
    if isinstance(unwind_rva, int) and unwind_rva != 0 \
            and unwind_rva % _DWORD != 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_UNWIND_INFO_UNALIGNED,
            details={"index": index, "unwind_info_rva": unwind_rva,
                     "alignment": _DWORD},
        ))

    if unwind is None:
        return

    # Parser-reported decode pathologies + derived version/flag anomalies,
    # collapsed to a single first-matching reason for determinism.
    unwind_errors = list(unwind.get("errors", []) or [])

    version = unwind.get("version")
    if isinstance(version, int) and version not in _VALID_UNWIND_VERSIONS \
            and "unwind_version_invalid" not in unwind_errors:
        unwind_errors.append("unwind_version_invalid")

    flags = unwind.get("flags")
    if isinstance(flags, int) and (flags & ~_UNW_FLAG_KNOWN_MASK) != 0 \
            and "unwind_flags_reserved_bits" not in unwind_errors:
        unwind_errors.append("unwind_flags_reserved_bits")

    unwind_reason = _first_matching(unwind_errors, _UNWIND_ERROR_PRIORITY)
    if unwind_reason != "unknown":
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXCEPTION_UNWIND_INFO_INVALID,
            details={"index": index, "reason": unwind_reason,
                     "version": version, "flags": flags,
                     "unwind_info_rva": unwind_rva},
        ))

    # ---- Chained unwind info ----
    # If UNW_FLAG_CHAININFO is set the trailing shared field is an
    # image-relative pointer to the *primary* RUNTIME_FUNCTION. A missing,
    # out-of-bounds, self-referential, or unaligned target is malformed.
    is_chained = bool(unwind.get("is_chained")) or \
        (isinstance(flags, int) and (flags & _UNW_FLAG_CHAININFO) != 0)
    if is_chained:
        chained_rva = unwind.get("chained_rva")
        reason = _chain_target_reason(chained_rva, unwind_rva, size_of_image)
        if reason is not None:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXCEPTION_UNWIND_CHAIN_INVALID,
                details={"index": index, "chained_rva": chained_rva,
                         "unwind_info_rva": unwind_rva, "reason": reason},
            ))


# =================================================================
# Helpers
# =================================================================

def _out_of_bounds_fields(begin: Optional[int], end: Optional[int],
                          unwind_rva: Optional[int],
                          size_of_image: Optional[int]) -> List[str]:
    """
    Return the fixed-order list of RVA field names that fall outside the
    mapped image. Empty when everything is in bounds or bounds are unknown.
    """
    if not isinstance(size_of_image, int):
        return []
    out: List[str] = []
    if isinstance(begin, int) and (begin < 0 or begin >= size_of_image):
        out.append("begin_rva")
    if isinstance(end, int) and (end < 0 or end > size_of_image):
        out.append("end_rva")
    if isinstance(unwind_rva, int) and unwind_rva != 0 \
            and (unwind_rva < 0 or unwind_rva >= size_of_image):
        out.append("unwind_info_rva")
    return out


def _chain_target_reason(chained_rva: Optional[int],
                         unwind_rva: Optional[int],
                         size_of_image: Optional[int]) -> Optional[str]:
    """
    Classify a chained-unwind pointer. Returns a sub-reason string when the
    target is malformed, else None. Ordered so the first applicable wins.
    """
    if not isinstance(chained_rva, int) or chained_rva == 0:
        return "chain_target_missing"
    if chained_rva % _DWORD != 0:
        return "chain_target_unaligned"
    if isinstance(size_of_image, int) and \
            (chained_rva < 0 or chained_rva >= size_of_image):
        return "chain_target_out_of_bounds"
    if isinstance(unwind_rva, int) and chained_rva == unwind_rva:
        return "chain_self_reference"
    return None


def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first error tag from `candidates` that appears in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
