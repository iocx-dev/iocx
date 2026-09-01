# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the import-table structure produced by parser pe_imports.

Absence of an import directory is NOT a structural defect - a few legitimate
binaries (resource-only DLLs, some drivers) import nothing. We only emit
codes when the directory is present and structurally malformed.

PLACEMENT IS NOT CHECKED HERE. The import directory (index 1) and the IAT
directory (index 12) are both plain RVAs, so the RVA-graph backbone (2.5)
already owns their placement, mapping, bounds and mutual-overlap truth. This
validator deliberately defers, in the same way relocations (2.13) and debug
(2.14) do, rather than asserting locally and double-counting.

The bound-import directory (index 11) is a separate structure that the
parser does not decode; descriptor-level bound STATE is interpreted here,
but the BOUND_IMPORT table itself is out of scope.

Reason codes emitted:
  IMPORT_DIRECTORY_INVALID_HEADER
  IMPORT_TABLE_TRUNCATED
  IMPORT_DESCRIPTOR_INVALID
  IMPORT_DLL_NAME_INVALID
  IMPORT_ENTRY_INVALID
"""

from typing import Any, Dict, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from .decorators import depends_on


# Priority-resolved sub-reasons. First match wins, so the ordering encodes
# which fault is the more fundamental when an entry carries several.
#
# Every tag the parser can place in the corresponding list appears here.
# A tag with no entry is silently dropped by _first_matching, so these lists
# are the parser->validator contract and must be kept exhaustive.

# descriptor["errors"], DLL-name class.
# Ordered: the RVA itself, then read faults from _read_asciiz, then content
# faults from the three-way split. The read tags and the content tags are
# mutually exclusive in practice (a non-None err skips the content check), so
# their relative order is defensive rather than load-bearing.
_DLL_NAME_ERROR_PRIORITY = [
    "dll_name_rva_zero",
    "rva_zero",
    "read_failed",
    "empty_read",
    "unterminated",
    "non_ascii",
    "dll_name_empty",
    "dll_name_not_printable",
    "dll_name_too_long",
]

# descriptor["errors"], thunk-source class. Mutually exclusive by
# construction: the parser returns immediately after appending either.
_THUNK_SOURCE_ERROR_PRIORITY = [
    "names_unrecoverable_bound_no_int",
    "no_thunk_array",
]

# entry["errors"].
# Ordered by decode stage: the ordinal path, then IMAGE_IMPORT_BY_NAME read
# faults, then name content faults.
_ENTRY_ERROR_PRIORITY = [
    "ordinal_zero",
    "name_rva_zero",
    "name_read_failed",
    "name_too_short",
    "hint_unpack_failed",
    "name_unterminated",
    "name_non_ascii",
    "name_empty",
    "name_not_printable",
]

# Cap on per-entry issues raised for a single descriptor, so a hostile
# import table cannot flood the stream. The true count is always in details.
_MAX_ENTRY_ISSUES_PER_DESCRIPTOR = 32


@depends_on("internal")
def validate_imports(internal: InternalMetadata) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    imp = internal.get("import_struct")
    if imp is None:
        return issues  # no import directory - not a defect

    # Top-level decode failure short-circuits: without a descriptor array
    if imp.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.IMPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "top_level_decode",
                     "errors": list(imp["errors"])},
        ))
        return issues

    _validate_truncations(imp, issues)
    _validate_descriptors(imp, issues)

    return issues


# =================================================================
# Truncations
# =================================================================

def _validate_truncations(imp: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """
    One issue per parser truncation tag, so the consumer sees one issue per
    truncated table rather than a single bundled report.

    Note the thunk-array tags are prefixed by the array actually read - `int`
    when OriginalFirstThunk was present, `iat_fallback` when the parser fell
    back to FirstThunk. That distinction is preserved verbatim in `table` so
    a consumer can tell which array was short.
    """
    for tag in imp.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.IMPORT_TABLE_TRUNCATED,
            details={"table": tag},
        ))


# =================================================================
# Descriptors
# =================================================================

def _validate_descriptors(imp: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    for descriptor in imp.get("descriptors", []) or []:
        index = descriptor.get("index")
        errors = descriptor.get("errors", []) or []

        # ---- DLL name ----
        reason = _first_matching(errors, _DLL_NAME_ERROR_PRIORITY)
        if reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.IMPORT_DLL_NAME_INVALID,
                details={"index": index,
                         "dll_name_rva": descriptor.get("name_rva"),
                         "dll_name": descriptor.get("dll_name"),
                         "sub_reason": reason},
            ))

        # ---- Thunk source ----
        # A descriptor with no readable name source names no imports at all.
        # Distinct from the DLL-name class: the module is identified, its
        # imported symbols are not.
        reason = _first_matching(errors, _THUNK_SOURCE_ERROR_PRIORITY)
        if reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.IMPORT_DESCRIPTOR_INVALID,
                details={"index": index,
                         "dll_name": descriptor.get("dll_name"),
                         "bound_state": descriptor.get("bound_state"),
                         "original_first_thunk":
                             descriptor.get("original_first_thunk"),
                         "first_thunk": descriptor.get("first_thunk"),
                         "sub_reason": reason},
            ))

        _validate_entries(descriptor, issues)


def _validate_entries(descriptor: Dict[str, Any],
                      issues: List[StructuralIssue]) -> None:
    """
    Emit per-import-entry issues, at most one per entry, priority-resolved.

    Emission is capped so a hostile table cannot flood the stream;
    `invalid_entry_count` always carries the true total.
    """
    descriptor_index = descriptor.get("index")
    dll_name = descriptor.get("dll_name")

    invalid: List[Dict[str, Any]] = []
    for entry in descriptor.get("imports", []) or []:
        entry_errors = entry.get("errors", []) or []
        if not entry_errors:
            continue
        reason = _first_matching(entry_errors, _ENTRY_ERROR_PRIORITY)
        if reason == "unknown":
            continue
        invalid.append({"entry": entry, "sub_reason": reason})

    if not invalid:
        return

    for item in invalid[:_MAX_ENTRY_ISSUES_PER_DESCRIPTOR]:
        entry = item["entry"]
        issues.append(StructuralIssue(
            issue=ReasonCodes.IMPORT_ENTRY_INVALID,
            details={
                "descriptor_index": descriptor_index,
                "dll_name": dll_name,
                "entry_index": entry.get("index"),
                "is_ordinal": entry.get("is_ordinal"),
                "ordinal": entry.get("ordinal"),
                "name": entry.get("name"),
                "name_rva": entry.get("name_rva"),
                "sub_reason": item["sub_reason"],
                "invalid_entry_count": len(invalid),
            },
        ))


# =================================================================
# Helpers
# =================================================================

def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first tag from `candidates` present in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
