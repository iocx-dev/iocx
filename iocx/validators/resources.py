# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the resource directory tree produced by parser pe_resources.

Absence of a resource directory is NOT a structural defect. Neither is the
absence of a .rsrc section: some producers place resources elsewhere, and
this validator's bounds checks are all expressed against .rsrc, so without
it there is nothing to compare against and we stay silent rather than
guess.

Parser tombstone tags consumed here:
  entry_decode_failed             - one entry in a directory was unreadable
  directory_entries_unavailable   - a directory's entry list was unreadable
  string_table_walk_failed        - the RT_STRING traversal raised

All three describe recoverability rather than placement, so they map to
their own codes and never displace the bounds findings below.
"""

from typing import Any, Dict, List, Set

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# Per-directory parser tags, priority-resolved so a directory carrying both
# reports the more fundamental one. An unreadable entry LIST subsumes any
# per-entry failure, because no entry was reached at all.
_DIRECTORY_ERROR_PRIORITY = [
    "directory_entries_unavailable",
    "entry_decode_failed",
]


@depends_on("internal", "analysis")
def validate_resources(metadata: InternalMetadata,
                       analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    resources = metadata.get("resources_struct")
    if not resources:
        return issues  # No resource directory -> no issues

    sections = analysis["sections"]
    file_size = analysis["file_size"]
    overlay_offset = analysis["overlay_offset"]

    # ---------------------------------------------------------
    # Locate .rsrc section
    # ---------------------------------------------------------
    rsrc_section = next(
        (sec for sec in sections if sec["name"].lower() == ".rsrc"), None)
    if rsrc_section is None:
        return issues  # No resource section -> nothing to validate

    rsrc_va = rsrc_section["virtual_address"]
    rsrc_vs = rsrc_section["virtual_size"]

    def rva_in_rsrc(rva: int, size: int = 0) -> bool:
        return rsrc_va <= rva and (rva + size) <= (rsrc_va + rsrc_vs)

    def va_overlaps_section(start: int, size: int, sec: Dict[str, Any]) -> bool:
        end = start + size
        sec_start = sec["virtual_address"]
        sec_end = sec_start + sec["virtual_size"]
        return max(start, sec_start) < min(end, sec_end)

    def raw_overlaps_section(raw_start: int, size: int,
                             sec: Dict[str, Any]) -> bool:
        end = raw_start + size
        sec_start = sec["raw_address"]
        sec_end = sec_start + sec["raw_size"]
        return max(raw_start, sec_start) < min(end, sec_end)

    visited_dirs: Set[int] = set()

    # ---------------------------------------------------------
    # Recursive directory validation
    # ---------------------------------------------------------
    def validate_directory(dir_node: Dict[str, Any], depth: int = 0) -> None:
        rva = dir_node["rva"]
        size = dir_node["size"]

        # The directory node itself must fit wholly inside .rsrc.
        #
        # Two distinct malformations reach here:
        #   * the ROOT directory lies outside .rsrc entirely, or
        #   * a CHILD starts inside .rsrc but its extent overflows the end -
        #     the caller's entry check tests target_rva WITHOUT a size, so
        #     such a child passes there and is caught here.
        #
        # A child lying wholly outside is already reported by the caller as
        # RESOURCE_ENTRY_OUT_OF_BOUNDS, and its `continue` prevents descent,
        # so the two codes never double-count. `depth` distinguishes the
        # cases: depth 0 is the root, deeper values are the overflow case.
        if not rva_in_rsrc(rva, size):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS,
                details={"rva": rva, "size": size, "depth": depth,
                         "rsrc_start": rsrc_va, "rsrc_end": rsrc_va + rsrc_vs},
            ))
            return

        entries = dir_node["entries"]

        # Reserved: unreachable while the parser derives size from the entry
        # count (minimum 16). Only becomes live if size is ever sourced from
        # the on-disk IMAGE_RESOURCE_DIRECTORY header instead.
        if size == 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH,
                details={"rva": rva},
            ))
            return

        # Loop detection
        if rva in visited_dirs:
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_LOOP,
                details={"rva": rva},
            ))
            return
        visited_dirs.add(rva)

        # ---- Parser-level decode failures for THIS directory ----
        # Reported after the placement and loop checks, so a directory we
        # decline to process does not also report its contents. The count is
        # carried because one tag may stand for several skipped entries, and
        # the gap between `size` and len(entries) is only interpretable with
        # it.
        dir_errors = dir_node.get("errors") or []
        reason = _first_matching(dir_errors, _DIRECTORY_ERROR_PRIORITY)
        if reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_ENTRY_UNREADABLE,
                details={"rva": rva, "depth": depth, "sub_reason": reason,
                         "failed_entry_count": dir_errors.count(
                             "entry_decode_failed"),
                         "declared_size": size,
                         "decoded_entries": len(entries)},
            ))

        # Language layer (depth 2) must use integer LCIDs:
        # Per PE spec, the Type -> Name -> Language tree's deepest directory
        # layer is keyed by language ID. Named entries here are malformed.
        if depth == 2:
            for e in entries:
                if e["name"] is not None and e["id"] is None:
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID,
                        details={"rva": rva, "name": e["name"]},
                    ))

        # Entries
        for entry in entries:
            if entry["is_directory"]:
                target = entry["directory"]
                target_rva = target["rva"]

                if not rva_in_rsrc(target_rva):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS,
                        details={"directory_rva": rva,
                                 "target_rva": target_rva},
                    ))
                    continue

                validate_directory(target, depth + 1)
                continue

            # Data entries should only appear at depth 2 (Language layer):
            # A data leaf at depth 0 or 1 means the tree shape violates the
            # Type -> Name -> Language hierarchy.
            if depth != 2:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH,
                    details={"rva": rva, "depth": depth,
                             "data_rva": entry["data_rva"]},
                ))

            # ------------------------------
            # Data entry
            # ------------------------------
            data_rva = entry["data_rva"]
            data_size = entry["data_size"]
            data_raw = entry["raw_offset"]

            # Zero-size data
            if data_size == 0:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_rva": data_rva, "data_size": data_size},
                ))
                continue

            # RVA bounds
            if not rva_in_rsrc(data_rva, data_size):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_rva": data_rva, "data_size": data_size},
                ))
                continue

            # Raw bounds (data_raw == -1 sentinel from a guarded RVA->offset
            # lookup also lands here, preserving the existing reason code).
            if data_raw < 0 or data_raw + data_size > file_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_raw": data_raw, "data_size": data_size,
                             "file_size": file_size},
                ))
                continue

            # Overlay overlap (inclusive check)
            if data_raw <= overlay_offset < data_raw + data_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                    details={"data_raw": data_raw, "data_size": data_size,
                             "overlay_offset": overlay_offset},
                ))

            # Raw overlap with other sections. Stops at the first
            # intersecting section: a blob crossing several reports once.
            for sec in sections:
                if sec is rsrc_section:
                    continue
                if raw_overlaps_section(data_raw, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_raw": data_raw, "data_size": data_size,
                                 "section": sec["name"]},
                    ))
                    break

            # VA overlap with other sections. Independent of the raw check
            # above, so a blob may report once per check.
            for sec in sections:
                if sec is rsrc_section:
                    continue
                if va_overlaps_section(data_rva, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_rva": data_rva, "data_size": data_size,
                                 "section": sec["name"]},
                    ))
                    break

    # ---------------------------------------------------------
    # Validate root directory
    # ---------------------------------------------------------
    validate_directory(resources["root"])

    # ---------------------------------------------------------
    # String table validation
    # ---------------------------------------------------------
    # A walk failure and a genuine absence of RT_STRING resources both leave
    # string_tables empty, so the parser records the failure explicitly.
    # Without this the two are indistinguishable and a malformed subtree is
    # reported as clean. Deliberately does NOT return: a partial walk still
    # has collected tables worth bounds-checking.
    if "string_table_walk_failed" in (resources.get("errors") or []):
        issues.append(StructuralIssue(
            issue=ReasonCodes.RESOURCE_STRING_TABLE_UNREADABLE,
            details={"sub_reason": "walk_failed",
                     "collected_tables": len(
                         resources.get("string_tables") or [])},
        ))

    # One issue per file rather than per table: a corrupt string-table
    # region is a property of the resource section, and reporting every
    # entry would flood on a systematically broken tree.
    for st in resources.get("string_tables", []):
        rva = st["rva"]
        size = st["size"]
        if not rva_in_rsrc(rva, size):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT,
                details={"rva": rva, "size": size},
            ))
            break

    return issues


def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first tag from `candidates` present in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
