from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def validate_optional_header(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    opt = metadata.get("optional_header") or {}
    size_of_image = opt.get("size_of_image")
    if not isinstance(size_of_image, int) or size_of_image <= 0:
        return issues

    max_end = 0
    for sec in analysis.get("sections", []):
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if not isinstance(va, int) or not isinstance(vs, int):
            continue
        max_end = max(max_end, va + vs)

    if max_end > size_of_image:
        issues.append(StructuralIssue(
            issue=ReasonCodes.OPTIONAL_HEADER_INCONSISTENT_SIZE,
            details={"size_of_image": size_of_image, "max_section_end": max_end},
        ))

    return issues
