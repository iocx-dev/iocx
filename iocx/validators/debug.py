# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the debug-directory structure produced by parser pe_debug.

Absence of a debug directory is NOT a structural defect. We only emit
codes when the directory is present and structurally malformed.

Placement ownership: directory->section placement for the debug directory
(dir 6) is owned by the rva_graph validator, which runs earlier in the
dispatcher. This validator therefore descends into entry contents only and
does NOT re-check directory placement, to avoid double-counting. (The
per-entry AddressOfRawData check below is a distinct, content-level fact:
it maps each entry's *data region*, which rva_graph does not inspect.)

This validator covers:
  - IMAGE_DEBUG_DIRECTORY entry integrity
  - debug entry data-region RVA validity
  - truncated / malformed entry handling

Reason codes emitted:
  DEBUG_DIRECTORY_INVALID_HEADER
  DEBUG_TABLE_TRUNCATED
  DEBUG_DIRECTORY_ENTRY_MALFORMED
  DEBUG_ENTRY_RVA_INVALID
"""

from typing import Any, Dict, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on
from ._directory_invariants import region_in_any_section

# Priority-resolved per-entry pathologies. First match wins.
_ENTRY_ERROR_PRIORITY = [
    "entry_unpack_failed",
    "codeview_read_failed",
    "codeview_too_short",
    "codeview_rsds_truncated",
    "codeview_nb10_truncated",
    "codeview_signature_unknown",
    "pdb_path_unterminated",
    "pdb_path_non_ascii",
]


@depends_on("internal", "analysis")
def validate_debug(metadata: InternalMetadata,
                   analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    debug = metadata.get("debug_struct")
    if debug is None:
        return issues  # no debug directory — not a defect

    # ---- Top-level decode failures short-circuit ----
    if debug.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.DEBUG_DIRECTORY_INVALID_HEADER,
            details={"reason": "top_level_decode",
                     "errors": list(debug["errors"])},
        ))
        return issues

    # NOTE: directory placement is intentionally NOT checked here — it is
    # owned by rva_graph. See module docstring.
    _validate_truncations(debug, issues)
    _validate_entries(debug, analysis, issues)

    return issues


# =================================================================
# Truncations
# =================================================================

def _validate_truncations(debug: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """Map parser truncation tags to one issue per truncated region."""
    for tag in debug.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.DEBUG_TABLE_TRUNCATED,
            details={"region": tag},
        ))


# =================================================================
# Entry-level validation
# =================================================================

def _validate_entries(debug: Dict[str, Any],
                      analysis: AnalysisDict,
                      issues: List[StructuralIssue]) -> None:
    """Emit per-entry malformation and data-region RVA issues."""
    for entry in debug.get("entries", []) or []:
        index = entry.get("index")
        entry_errors = entry.get("errors", []) or []

        reason = _first_matching(entry_errors, _ENTRY_ERROR_PRIORITY)
        if reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.DEBUG_DIRECTORY_ENTRY_MALFORMED,
                details={"index": index,
                         "type": entry.get("type"),
                         "type_name": entry.get("type_name"),
                         "reason": reason},
            ))

        _validate_entry_rva(entry, analysis, issues)


def _validate_entry_rva(entry: Dict[str, Any],
                        analysis: AnalysisDict,
                        issues: List[StructuralIssue]) -> None:
    """
    Flag a debug entry whose AddressOfRawData region does not map to any
    section. Entries with no RVA (file-pointer-only) are not flagged here.

    This is a content-level check on the entry's data region, distinct from
    the directory placement owned by rva_graph.
    """
    addr_raw = entry.get("address_of_raw_data")
    size_of_data = entry.get("size_of_data") or 0
    if not addr_raw:
        return

    mapped = region_in_any_section(addr_raw, size_of_data, analysis)
    if mapped is False:
        issues.append(StructuralIssue(
            issue=ReasonCodes.DEBUG_ENTRY_RVA_INVALID,
            details={"index": entry.get("index"),
                     "address_of_raw_data": addr_raw,
                     "size_of_data": size_of_data},
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
