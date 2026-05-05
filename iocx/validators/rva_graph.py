from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def validate_rva_graph(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories")
    opt = metadata.get("optional_header") or {}
    size_of_image = opt.get("size_of_image")

    if not isinstance(size_of_image, int) or not isinstance(dirs, list):
        return issues

    # -----------------------------
    # Out-of-range / malformed RVAs
    # -----------------------------
    for d in dirs:
        rva = d.get("rva")
        size = d.get("size")
        name = d.get("name") or d.get("index")

        if not isinstance(rva, int) or not isinstance(size, int):
            continue

        # Zero RVA + non-zero size
        if size > 0 and rva == 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE,
                details={
                    "directory": name,
                    "rva": rva,
                    "size": size,
                },
            ))

        # Out of range
        if rva + size > size_of_image:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE,
                details={
                    "directory": name,
                    "rva": rva,
                    "size": size,
                    "size_of_image": size_of_image,
                },
            ))

    # -----------------------------
    # Overlap detection (no ranges)
    # -----------------------------
    for i in range(len(dirs)):
        a = dirs[i]
        rva_a = a.get("rva")
        size_a = a.get("size")
        if not isinstance(rva_a, int) or not isinstance(size_a, int):
            continue
        end_a = rva_a + size_a

        for j in range(i + 1, len(dirs)):
            b = dirs[j]
            rva_b = b.get("rva")
            size_b = b.get("size")
            if not isinstance(rva_b, int) or not isinstance(size_b, int):
                continue
            end_b = rva_b + size_b

            if max(rva_a, rva_b) < min(end_a, end_b):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_OVERLAP,
                    details={
                        "directory_a": a.get("name") or a.get("index"),
                        "directory_b": b.get("name") or b.get("index"),
                    },
                ))

    return issues
