# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the base-relocation structure produced by parser pe_relocations.

Absence of a relocation directory is NOT a structural defect — stripped
or fixed-base binaries legitimately omit it. We only emit codes when the
directory is present and structurally malformed.

Placement ownership: directory->section placement for the relocation
directory (dir 5) is owned by the rva_graph validator, which runs earlier
in the dispatcher. This validator therefore descends into block contents
only and does NOT re-check placement, to avoid double-counting.

This validator covers:
  - IMAGE_BASE_RELOCATION block integrity
  - relocation entry RVA validity
  - truncated / malformed block handling

Reason codes emitted:
  RELOCATION_DIRECTORY_INVALID_HEADER
  RELOCATION_TABLE_TRUNCATED
  RELOCATION_BLOCK_MALFORMED
  RELOCATION_ENTRY_RVA_INVALID
"""

from typing import Any, Dict, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on
from ._directory_invariants import rva_in_any_section

# Priority-resolved block-level pathologies. First match wins for
# deterministic emission.
_BLOCK_ERROR_PRIORITY = [
    "size_of_block_too_small",
    "size_of_block_not_word_aligned",
    "entry_count_exceeds_max",
]

# Cap on how many invalid-entry issues a single block may raise, so a
# pathological block cannot flood the issue stream. The count is always
# reported in details regardless of how many individual issues emit.
_MAX_ENTRY_ISSUES_PER_BLOCK = 8


@depends_on("internal", "analysis")
def validate_relocations(metadata: InternalMetadata,
                         analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    reloc = metadata.get("relocation_struct")
    if reloc is None:
        return issues  # no relocation directory — not a defect

    # ---- Top-level decode failures short-circuit ----
    if reloc.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.RELOCATION_DIRECTORY_INVALID_HEADER,
            details={"reason": "top_level_decode",
                     "errors": list(reloc["errors"])},
        ))
        return issues

    # NOTE: directory placement is intentionally NOT checked here — it is
    # owned by rva_graph. See module docstring.
    _validate_truncations(reloc, issues)
    _validate_blocks(reloc, analysis, issues)

    return issues


# =================================================================
# Truncations
# =================================================================

def _validate_truncations(reloc: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """Map parser truncation tags to one issue per truncated region."""
    for tag in reloc.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.RELOCATION_TABLE_TRUNCATED,
            details={"region": tag},
        ))


# =================================================================
# Block-level validation
# =================================================================

def _validate_blocks(reloc: Dict[str, Any],
                     analysis: AnalysisDict,
                     issues: List[StructuralIssue]) -> None:
    """Emit per-block structural issues and per-entry RVA issues."""
    for block in reloc.get("blocks", []) or []:
        index = block.get("index")
        block_errors = block.get("errors", []) or []

        reason = _first_matching(block_errors, _BLOCK_ERROR_PRIORITY)
        if reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.RELOCATION_BLOCK_MALFORMED,
                details={"index": index,
                         "page_rva": block.get("page_rva"),
                         "size_of_block": block.get("size_of_block"),
                         "reason": reason},
            ))

        _validate_block_entries(block, analysis, issues)


def _validate_block_entries(block: Dict[str, Any],
                            analysis: AnalysisDict,
                            issues: List[StructuralIssue]) -> None:
    """
    Flag relocation entries whose target RVA does not map to any section.
    ABSOLUTE (type 0) entries are padding and are never flagged.

    Conservative check: on well-formed binaries every fixup target maps to
    a section. Consider gating behind a strict-mode flag if real system
    binaries produce noise.
    """
    index = block.get("index")
    invalid_rvas: List[int] = []

    for entry in block.get("entries", []) or []:
        if entry.get("type") == 0:  # IMAGE_REL_BASED_ABSOLUTE — padding
            continue
        target_rva = entry.get("rva")
        mapped = rva_in_any_section(target_rva, analysis)
        if mapped is False:
            invalid_rvas.append(target_rva)

    if not invalid_rvas:
        return

    for target_rva in invalid_rvas[:_MAX_ENTRY_ISSUES_PER_BLOCK]:
        issues.append(StructuralIssue(
            issue=ReasonCodes.RELOCATION_ENTRY_RVA_INVALID,
            details={"block_index": index,
                     "rva": target_rva,
                     "invalid_entry_count": len(invalid_rvas)},
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
