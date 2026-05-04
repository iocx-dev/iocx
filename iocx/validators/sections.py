from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue

# PE section characteristics flags (subset)
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

CODE_LIKE_NAMES = {".text", "text", "code"}


def _is_ascii_printable(name: str) -> bool:
    try:
        return all(32 <= ord(ch) < 127 for ch in name)
    except TypeError:
        return False


def _is_padding_name(name: str) -> bool:
    stripped = name.strip("\x00").strip()
    return stripped == ""


def validate_sections(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []
    sections: List[Dict[str, Any]] = analysis.get("sections", []) or []

    for sec in sections:
        name = (sec.get("name") or "").strip()
        chars = sec.get("characteristics")

        if not isinstance(chars, int):
            continue

        executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        writable = bool(chars & IMAGE_SCN_MEM_WRITE)
        has_code = bool(chars & IMAGE_SCN_CNT_CODE)
        discardable = bool(chars & IMAGE_SCN_MEM_DISCARDABLE)

        # 1) RWX sections
        if executable and writable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_RWX,
                details={"section": name, "characteristics": chars},
            ))

        # 2) Code flag but not executable
        if has_code and not executable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_NON_EXECUTABLE_CODE_LIKE,
                details={"section": name, "characteristics": chars},
            ))

        # 3) Code-like name but not executable
        if name.lower() in CODE_LIKE_NAMES and not executable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_EXEC_IN_SUSPICIOUS_NAME,
                details={"section": name, "characteristics": chars},
            ))

        # 4) Non-ASCII or deceptive names
        if not _is_ascii_printable(name):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_NAME_NON_ASCII,
                details={"section": name},
            ))
        elif _is_padding_name(name):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_NAME_EMPTY_OR_PADDING,
                details={"section": name},
            ))

        # 5) Impossible flag combinations
        if discardable and executable and writable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_IMPOSSIBLE_FLAGS,
                details={"section": name, "characteristics": chars},
            ))

    return issues

