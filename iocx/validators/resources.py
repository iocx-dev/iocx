from typing import Dict, Any, List, Set
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def validate_resources(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    resources = metadata.get("resources_struct")
    if not resources:
        return issues # No resource directory → no issues

    sections = analysis["sections"]
    file_size = analysis["file_size"]
    overlay_offset = analysis["overlay_offset"]

    # ---------------------------------------------------------
    # Locate .rsrc section
    # ---------------------------------------------------------
    rsrc_section = next((sec for sec in sections if sec["name"].lower() == ".rsrc"), None)
    if rsrc_section is None:
        return issues # No resource section → nothing to validate

    rsrc_va = rsrc_section["virtual_address"]
    rsrc_vs = rsrc_section["virtual_size"]
    rsrc_raw = rsrc_section["raw_address"]
    rsrc_raw_size = rsrc_section["raw_size"]

    def rva_in_rsrc(rva: int, size: int = 0) -> bool:
        return rsrc_va <= rva and (rva + size) <= (rsrc_va + rsrc_vs)

    def va_overlaps_section(start: int, size: int, sec: Dict[str, Any]) -> bool:
        end = start + size
        sec_start = sec["virtual_address"]
        sec_end = sec_start + sec["virtual_size"]
        return max(start, sec_start) < min(end, sec_end)

    def raw_overlaps_section(raw_start: int, size: int, sec: Dict[str, Any]) -> bool:
        end = raw_start + size
        sec_start = sec["raw_address"]
        sec_end = sec_start + sec["raw_size"]
        return max(raw_start, sec_start) < min(end, sec_end)

    visited_dirs: Set[int] = set()

    # ---------------------------------------------------------
    # Recursive directory validation
    # ---------------------------------------------------------
    def validate_directory(dir_node: Dict[str, Any]) -> None:
        rva = dir_node["rva"]
        size = dir_node["size"]

        # Skip if the directory is not inside .rsrc
        if not rva_in_rsrc(rva, size):
            return

        entries = dir_node["entries"]

        # Zero-length directory
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

        # Entries
        for entry in entries:
            if entry["is_directory"]:
                target = entry["directory"]
                target_rva = target["rva"]

                if not rva_in_rsrc(target_rva):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS,
                        details={"directory_rva": rva, "target_rva": target_rva},
                    ))
                    continue

                validate_directory(target)
                continue

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

            # Raw bounds
            if data_raw < 0 or data_raw + data_size > file_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
                    details={"data_raw": data_raw, "data_size": data_size, "file_size": file_size},
                ))
                continue

            # Overlay overlap (inclusive check)
            if data_raw <= overlay_offset < data_raw + data_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                    details={"data_raw": data_raw, "data_size": data_size, "overlay_offset": overlay_offset},
                ))

            # Raw overlap with other sections
            for sec in sections:
                if sec is rsrc_section:
                    continue
                if raw_overlaps_section(data_raw, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_raw": data_raw, "data_size": data_size, "section": sec["name"]},
                    ))
                    break

            # VA overlap with other sections
            for sec in sections:
                if sec is rsrc_section:
                    continue
                if va_overlaps_section(data_rva, data_size, sec):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA,
                        details={"data_rva": data_rva, "data_size": data_size, "section": sec["name"]},
                    ))
                    break

    # ---------------------------------------------------------
    # Validate root directory
    # ---------------------------------------------------------
    validate_directory(resources["root"])

    # ---------------------------------------------------------
    # String table validation
    # ---------------------------------------------------------
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
