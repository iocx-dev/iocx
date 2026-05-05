from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _map_rva_to_section(sections: List[Dict[str, Any]], rva: int):
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if isinstance(va, int) and isinstance(vs, int):
            if va <= rva < va + vs:
                return sec
    return None


def validate_entrypoint(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    # --- Extract entrypoint ---
    header_ext = [
        e for e in analysis.get("extended", [])
        if isinstance(e, dict) and e.get("value") == "header"
    ]
    if not header_ext:
        return issues

    ep = header_ext[0]["metadata"].get("entry_point")
    if not isinstance(ep, int):
        return issues

    sections = analysis.get("sections", [])
    if not sections:
        return issues

    # --- A. EP must map to a valid section ---
    sec = _map_rva_to_section(sections, ep)
    if sec is None:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_OUT_OF_BOUNDS,
            details={"entry_point": ep},
        ))
        return issues # cannot continue without a section

    name = sec.get("name")
    chars = sec.get("characteristics", 0)

    # --- B. Section must be executable ---
    executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
    if not executable:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_SECTION_NOT_EXECUTABLE,
            details={"entry_point": ep, "section": name, "characteristics": chars},
        ))

    # --- C. EP must not fall into truncated or zero-length regions ---
    va = sec.get("virtual_address")
    vs = sec.get("virtual_size")
    raw = sec.get("raw_address")
    raw_size = sec.get("raw_size")

    # zero-length section
    if isinstance(vs, int) and vs == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION,
            details={"entry_point": ep, "section": name, "reason": "zero_length_section"},
        ))

    # EP beyond virtual bounds
    if isinstance(va, int) and isinstance(vs, int) and ep >= va + vs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION,
            details={"entry_point": ep, "section": name, "reason": "beyond_virtual_size"},
        ))

    # --- D. EP must not point into overlays ---
    overlay_offset = analysis.get("overlay_offset")
    if isinstance(overlay_offset, int) and ep >= overlay_offset:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_OVERLAY,
            details={"entry_point": ep, "overlay_offset": overlay_offset},
        ))

    return issues
