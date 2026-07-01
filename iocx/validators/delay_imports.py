# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the delay-load import structure produced by parser_delay_imports.

Absence of a delay-load directory is NOT a structural defect — most binaries
don't use delay-loading. We only emit codes when the directory is present
and structurally malformed.

This validator covers:
  - Parsing of IMAGE_DELAY_IMPORT_DESCRIPTOR
  - INT/IAT validation
  - DLL name RVA validation
  - Malformed descriptor handling

Reason codes emitted:
  DELAY_IMPORT_DIRECTORY_INVALID_HEADER
  DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS
  DELAY_IMPORT_TABLE_TRUNCATED
  DELAY_IMPORT_DESCRIPTOR_INVALID
  DELAY_IMPORT_DLL_NAME_INVALID
  DELAY_IMPORT_INT_IAT_MISMATCH
  DELAY_IMPORT_ENTRY_INVALID
  DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE
"""

from typing import Any, Dict, List, Optional

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# Priority-resolved sub-reasons for per-entry name/RVA pathologies.
# First-matching wins for deterministic emission.
_DLL_NAME_ERROR_PRIORITY = [
    "dll_name_rva_zero",
    "read_failed",
    "unterminated",
    "dll_name_not_printable",
    "non_ascii",
]

_INT_RVA_ERROR_PRIORITY = [
    "int_rva_zero",
    "int_truncated",
    "int_read_failed",
    "int_max_exceeded",
    "int_unpack_failed",
]

_IAT_RVA_ERROR_PRIORITY = [
    "iat_rva_zero",
    "iat_truncated",
    "iat_read_failed",
    "iat_max_exceeded",
    "iat_unpack_failed",
]

_ENTRY_ERROR_PRIORITY = [
    "int_entry_missing",
    "int_entry_zero",
    "ordinal_zero",
    "name_read_failed",
    "name_too_short",
    "hint_unpack_failed",
    "name_unterminated",
    "name_non_ascii",
    "name_not_printable",
]


@depends_on("internal", "analysis")
def validate_delay_imports(metadata: InternalMetadata,
                           analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    di = metadata.get("delay_import_struct")
    if di is None:
        return issues  # no delay-load directory — not a defect

    size_of_image = analysis.get("size_of_image")

    # ---- Top-level decode failures short-circuit ----
    if di.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.DELAY_IMPORT_DIRECTORY_INVALID_HEADER,
            details={"reason": "top_level_decode",
                     "errors": list(di["errors"])},
        ))
        return issues

    _validate_placement(di, size_of_image, issues)
    _validate_truncations(di, issues)
    _validate_descriptors(di, size_of_image, issues)

    return issues


# =================================================================
# Placement
# =================================================================

def _validate_placement(di: Dict[str, Any],
                        size_of_image: Optional[int],
                        issues: List[StructuralIssue]) -> None:
    """
    The delay-load directory must lie within the PE image (SizeOfImage).
    """
    rva = di.get("rva")
    size = di.get("size") or 0

    # Skip placement check if the analysis layer didn't populate
    # size_of_image. This shouldn't happen in normal operation — if it
    # does, an upstream bug needs investigating, not a placement issue.
    if rva is None or size_of_image is None:
        return

    if rva + size > size_of_image:
        issues.append(StructuralIssue(
            issue=ReasonCodes.DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS,
            details={"rva": rva, "size": size,
                     "size_of_image": size_of_image},
        ))


# =================================================================
# Truncations
# =================================================================

def _validate_truncations(di: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """
    Map parser truncation tags to a single reason code with structured
    details. Each tag becomes one issue so the consumer sees one issue
    per truncated table.
    """
    for tag in di.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.DELAY_IMPORT_TABLE_TRUNCATED,
            details={"table": tag},
        ))


# =================================================================
# Descriptor-level validation
# =================================================================

def _validate_descriptors(di: Dict[str, Any],
                          size_of_image: Optional[int],
                          issues: List[StructuralIssue]) -> None:
    """
    Walk each IMAGE_DELAY_IMPORT_DESCRIPTOR and emit per-descriptor
    structural issues.
    """
    descriptors = di.get("descriptors", []) or []
    is_64bit = di.get("is_64bit", False)

    for descriptor in descriptors:
        index = descriptor.get("index")
        descriptor_errors = descriptor.get("errors", []) or []

        # ---- v0 (legacy VA mode) attribute check ----
        # Pre-Windows 2000 binaries use raw VAs in delay-load tables
        # rather than RVAs. Vanishingly rare in modern binaries.
        if not descriptor.get("attributes_v1", True):
            issues.append(StructuralIssue(
                issue=ReasonCodes.DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE,
                details={"index": index,
                         "attributes": descriptor.get("attributes")},
            ))

        # ---- DLL name validation ----
        dll_name_reason = _first_matching(
            descriptor_errors, _DLL_NAME_ERROR_PRIORITY
        )
        if dll_name_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.DELAY_IMPORT_DLL_NAME_INVALID,
                details={"index": index,
                         "dll_name_rva": descriptor.get("dll_name_rva"),
                         "dll_name": descriptor.get("dll_name"),
                         "reason": dll_name_reason},
            ))

        # ---- INT/IAT table-level errors ----
        # INT and IAT each produce their own descriptor-level errors
        # via the parser. Emit one issue per affected table.
        int_reason = _first_matching(
            descriptor_errors, _INT_RVA_ERROR_PRIORITY
        )
        if int_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.DELAY_IMPORT_DESCRIPTOR_INVALID,
                details={"index": index,
                         "table": "int",
                         "reason": int_reason,
                         "int_rva": descriptor.get("int_rva")},
            ))

        iat_reason = _first_matching(
            descriptor_errors, _IAT_RVA_ERROR_PRIORITY
        )
        if iat_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.DELAY_IMPORT_DESCRIPTOR_INVALID,
                details={"index": index,
                         "table": "iat",
                         "reason": iat_reason,
                         "iat_rva": descriptor.get("iat_rva")},
            ))

        # ---- INT/IAT length mismatch ----
        # This is a strong signal of malformation. Emitted as its own
        # reason code rather than folded into DESCRIPTOR_INVALID because
        # it's a cross-table consistency check, not a per-table issue.
        if "int_iat_length_mismatch" in descriptor_errors:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DELAY_IMPORT_INT_IAT_MISMATCH,
                details={"index": index,
                         "dll_name": descriptor.get("dll_name")},
            ))

        # ---- Per-import-entry validation ----
        _validate_import_entries(descriptor, issues)


def _validate_import_entries(descriptor: Dict[str, Any],
                             issues: List[StructuralIssue]) -> None:
    """
    Emit per-import-entry issues. Each malformed entry produces at most
    one issue with priority-resolved sub-reason.
    """
    descriptor_index = descriptor.get("index")
    imports = descriptor.get("imports", []) or []

    for entry in imports:
        entry_errors = entry.get("errors", []) or []
        if not entry_errors:
            continue

        reason = _first_matching(entry_errors, _ENTRY_ERROR_PRIORITY)
        if reason == "unknown":
            continue

        issues.append(StructuralIssue(
            issue=ReasonCodes.DELAY_IMPORT_ENTRY_INVALID,
            details={
                "descriptor_index": descriptor_index,
                "entry_index": entry.get("index"),
                "is_ordinal": entry.get("is_ordinal"),
                "ordinal": entry.get("ordinal"),
                "name": entry.get("name"),
                "name_rva": entry.get("name_rva"),
                "reason": reason,
            },
        ))


# =================================================================
# Helpers
# =================================================================

def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first error tag from `candidates` that appears in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
