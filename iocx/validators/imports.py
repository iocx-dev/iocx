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


def validate_import_directory(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories")
    sections = analysis.get("sections", [])
    if not isinstance(dirs, list) or not sections:
        return issues

    for d in dirs:
        name = (d.get("name") or "").lower()
        idx = d.get("index")
        if name == "import" or idx == 1:
            rva = d.get("rva")
            size = d.get("size")
            if not isinstance(rva, int) or not isinstance(size, int):
                continue

            if _map_rva_to_section(sections, rva) is None:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.IMPORT_RVA_INVALID,
                    details={"rva": rva, "size": size},
                ))

    return issues
