# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0
from typing import Dict, Any, List, Set
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on

@depends_on("internal", "analysis")
def validate_resources(metadata, analysis):
    issues = []
    resources = metadata.get("resources_struct")
    if not resources:
        return issues
    sections = analysis["sections"]
    file_size = analysis["file_size"]
    overlay_offset = analysis["overlay_offset"]
    rsrc_section = next((sec for sec in sections if sec["name"].lower() == ".rsrc"), None)
    if rsrc_section is None:
        return issues
    rsrc_va = rsrc_section["virtual_address"]
    rsrc_vs = rsrc_section["virtual_size"]

    def rva_in_rsrc(rva, size=0):
        return rsrc_va <= rva and (rva + size) <= (rsrc_va + rsrc_vs)
    def va_overlaps_section(start, size, sec):
        end = start + size
        s = sec["virtual_address"]; e = s + sec["virtual_size"]
        return max(start, s) < min(end, e)
    def raw_overlaps_section(raw_start, size, sec):
        end = raw_start + size
        s = sec["raw_address"]; e = s + sec["raw_size"]
        return max(raw_start, s) < min(end, e)

    visited_dirs = set()

    def validate_directory(dir_node: Dict[str, Any], depth: int = 0) -> None:
        rva = dir_node["rva"]
        size = dir_node["size"]

        # The directory node itself must fit wholly inside .rsrc.
        #
        # Two distinct malformations reach here:
        #   * the ROOT directory lies outside .rsrc entirely, or
        #   * a CHILD starts inside .rsrc but its extent overflows the end -
        #     the caller's entry check tests target_rva WITHOUT a size, so such
        #     a child passes there and is caught here.
        #
        # A child lying wholly outside is already reported by the caller as
        # RESOURCE_ENTRY_OUT_OF_BOUNDS, and its `continue` prevents descent, so
        # the two codes never double-count. `depth` distinguishes the cases:
        # depth 0 is the root, deeper values are the overflow case.
        if not rva_in_rsrc(rva, size):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS,
                details={"rva": rva, "size": size, "depth": depth,
                         "rsrc_start": rsrc_va, "rsrc_end": rsrc_va + rsrc_vs},
            ))
            return
        entries = dir_node["entries"]
        if size == 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH, details={"rva": rva}))
            return
        if rva in visited_dirs:
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_DIRECTORY_LOOP, details={"rva": rva}))
            return
        visited_dirs.add(rva)
        if depth == 2:
            for e in entries:
                if e["name"] is not None and e["id"] is None:
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID,
                        details={"rva": rva, "name": e["name"]}))
        for entry in entries:
            if entry["is_directory"]:
                target = entry["directory"]; target_rva = target["rva"]
                if not rva_in_rsrc(target_rva):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS,
                        details={"directory_rva": rva, "target_rva": target_rva}))
                    continue
                validate_directory(target, depth + 1)
                continue
            if depth != 2:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH,
                    details={"rva": rva, "depth": depth, "data_rva": entry["data_rva"]}))
            data_rva = entry["data_rva"]; data_size = entry["data_size"]; data_raw = entry["raw_offset"]
            if data_size == 0:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_rva": data_rva, "data_size": data_size})); continue
            if not rva_in_rsrc(data_rva, data_size):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_rva": data_rva, "data_size": data_size})); continue
            if data_raw < 0 or data_raw + data_size > file_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_raw": data_raw, "data_size": data_size,
                             "file_size": file_size})); continue
            if data_raw <= overlay_offset < data_raw + data_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                    details={"data_raw": data_raw, "data_size": data_size,
                             "overlay_offset": overlay_offset}))
            for sec in sections:
                if sec is rsrc_section: continue
                if raw_overlaps_section(data_raw, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_raw": data_raw, "data_size": data_size,
                                 "section": sec["name"]})); break
            for sec in sections:
                if sec is rsrc_section: continue
                if va_overlaps_section(data_rva, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_rva": data_rva, "data_size": data_size,
                                 "section": sec["name"]})); break

    validate_directory(resources["root"])
    for st in resources.get("string_tables", []):
        rva = st["rva"]; size = st["size"]
        if not rva_in_rsrc(rva, size):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT,
                details={"rva": rva, "size": size})); break
    return issues
