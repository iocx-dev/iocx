from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def _map_rva_to_section(sections: List[Dict[str, Any]], rva: int):
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if isinstance(va, int) and isinstance(vs, int):
            if va <= rva < va + vs:
                return sec
    return None


def validate_rva_graph(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories")
    sections = analysis.get("sections", [])

    if not isinstance(dirs, list) or not sections:
        return issues

    # Precompute directory ranges
    ranges = []
    for d in dirs:
        rva = d.get("rva")
        size = d.get("size")
        name = d.get("name") or d.get("index")

        if not isinstance(rva, int) or not isinstance(size, int):
            continue

        start = rva
        end = rva + size
        ranges.append((start, end, name, d))

        # 1) Directory must map to a valid section (unless zero-length)
        if size > 0:
            sec = _map_rva_to_section(sections, rva)
            if sec is None:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE,
                    details={"directory": name, "rva": rva, "size": size},
                ))
            else:
                va = sec.get("virtual_address")
                vs = sec.get("virtual_size")
                if isinstance(va, int) and isinstance(vs, int):
                    if end > va + vs:
                        issues.append(StructuralIssue(
                            issue=ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE,
                            details={
                                "directory": name,
                                "rva": rva,
                                "size": size,
                                "section": sec.get("name"),
                                "section_end": va + vs,
                            },
                        ))

        # Zero-length directories are allowed but still included for overlap logic

    # 2) Overlap detection (deterministic ordering)
    ranges.sort(key=lambda x: x[0])

    for i in range(len(ranges)):
        start_a, end_a, name_a, dir_a = ranges[i]
        for j in range(i + 1, len(ranges)):
            start_b, end_b, name_b, dir_b = ranges[j]

            # If B starts after A ends, no overlap possible
            if start_b >= end_a:
                break

            size_a = dir_a.get("size")
            size_b = dir_b.get("size")

            # Ignore zero-length + zero-length
            if size_a == 0 and size_b == 0:
                continue

            # Overlap condition
            if max(start_a, start_b) < min(end_a, end_b):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_OVERLAP,
                    details={
                        "directory_a": name_a,
                        "directory_b": name_b,
                        "range_a": [start_a, end_a],
                        "range_b": [start_b, end_b],
                    },
                ))

    return issues
