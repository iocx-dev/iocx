from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue

# PE section characteristics flags (subset)
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_READ = 0x40000000 # needed for contradictory flag checks

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

    opt = metadata.get("optional_header") or {}
    file_alignment = opt.get("file_alignment")
    size_of_headers = opt.get("size_of_headers")

    # ---------------------------------------------------------
    # Per‑section checks
    # ---------------------------------------------------------
    for sec in sections:
        name = (sec.get("name") or "").strip()
        chars = sec.get("characteristics")

        if not isinstance(chars, int):
            continue

        executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        writable = bool(chars & IMAGE_SCN_MEM_WRITE)
        readable = bool(chars & IMAGE_SCN_MEM_READ)
        has_code = bool(chars & IMAGE_SCN_CNT_CODE)
        discardable = bool(chars & IMAGE_SCN_MEM_DISCARDABLE)

        raw_addr = sec.get("raw_address")
        raw_size = sec.get("raw_size")
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")

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
                issue=ReasonCodes.SECTION_CODELIKE_NAME_NOT_EXECUTABLE,
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

        # 6) Raw alignment check
        if (
            isinstance(file_alignment, int)
            and isinstance(raw_addr, int)
            and isinstance(raw_size, int)
            and file_alignment > 0
        ):
            if raw_addr % file_alignment != 0:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.SECTION_RAW_MISALIGNED,
                    details={
                        "section": name,
                        "raw_address": raw_addr,
                        "raw_size": raw_size,
                        "file_alignment": file_alignment,
                    },
                ))

        # 7) Section overlaps headers
        if (
            isinstance(size_of_headers, int)
            and isinstance(raw_addr, int)
            and raw_addr < size_of_headers
        ):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_OVERLAPS_HEADERS,
                details={"section": name, "raw_address": raw_addr, "size_of_headers": size_of_headers},
            ))

        # 8) Zero-length section
        if (
            isinstance(vs, int)
            and isinstance(raw_size, int)
            and vs == 0
            and raw_size == 0
        ):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_ZERO_LENGTH,
                details={"section": name},
            ))

        # 9) Discardable + executable (even without writable)
        if discardable and executable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_DISCARDABLE_CODE,
                details={"section": name, "characteristics": chars},
            ))

        # 10) Contradictory flags
        if has_code and not readable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                details={"section": name, "reason": "code_without_read"},
            ))
        if writable and not readable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                details={"section": name, "reason": "write_without_read"},
            ))
        if executable and not readable:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_FLAGS_INCONSISTENT,
                details={"section": name, "reason": "exec_without_read"},
            ))

    # ---------------------------------------------------------
    # Raw overlap detection
    # ---------------------------------------------------------
    for i in range(len(sections)):
        a = sections[i]
        raw_a = a.get("raw_address")
        size_a = a.get("raw_size")
        if not isinstance(raw_a, int) or not isinstance(size_a, int):
            continue
        end_a = raw_a + size_a

        for j in range(i + 1, len(sections)):
            b = sections[j]
            raw_b = b.get("raw_address")
            size_b = b.get("raw_size")
            if not isinstance(raw_b, int) or not isinstance(size_b, int):
                continue
            end_b = raw_b + size_b

            if max(raw_a, raw_b) < min(end_a, end_b):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.SECTION_RAW_OVERLAP,
                    details={"section_a": a.get("name"), "section_b": b.get("name")},
                ))

    # ---------------------------------------------------------
    # Virtual overlap detection
    # ---------------------------------------------------------
    for i in range(len(sections)):
        a = sections[i]
        va_a = a.get("virtual_address")
        vs_a = a.get("virtual_size")
        if not isinstance(va_a, int) or not isinstance(vs_a, int):
            continue
        end_a = va_a + vs_a

        for j in range(i + 1, len(sections)):
            b = sections[j]
            va_b = b.get("virtual_address")
            vs_b = b.get("virtual_size")
            if not isinstance(va_b, int) or not isinstance(vs_b, int):
                continue
            end_b = va_b + vs_b

            if max(va_a, va_b) < min(end_a, end_b):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.SECTION_OVERLAP,
                    details={"section_a": a.get("name"), "section_b": b.get("name")},
                ))

    # ---------------------------------------------------------
    # Ordering checks
    # ---------------------------------------------------------
    # Raw order
    raw_addrs = [sec.get("raw_address") for sec in sections]
    if all(isinstance(x, int) for x in raw_addrs):
        if raw_addrs != sorted(raw_addrs):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_OUT_OF_ORDER_RAW,
                details={"raw_addresses": raw_addrs},
            ))

    # Virtual order
    vas = [sec.get("virtual_address") for sec in sections]
    if all(isinstance(x, int) for x in vas):
        if vas != sorted(vas):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SECTION_OUT_OF_ORDER_VIRTUAL,
                details={"virtual_addresses": vas},
            ))

    return issues
