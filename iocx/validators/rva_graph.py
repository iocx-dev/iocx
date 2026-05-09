from typing import Dict, Any, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# No directories are strictly required to be non-zero.
REQUIRED_NONZERO_DIRS: set[str] = set()


@depends_on("metadata", "analysis")
def validate_rva_graph(metadata: PublicMetadata, analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories") or []
    opt = metadata.get("optional_header") or {}
    sections = analysis.get("sections", []) or []

    size_of_image = opt.get("size_of_image")
    size_of_headers = opt.get("size_of_headers")
    overlay_offset = analysis.get("overlay_offset")

    if not isinstance(size_of_image, int):
        return issues

    # Build section ranges
    section_ranges = []
    zero_length_sections = set()
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        name = sec.get("name")
        if isinstance(va, int) and isinstance(vs, int):
            section_ranges.append((va, va + vs, name))
            if vs == 0:
                zero_length_sections.add(name)

    # ---------------------------------------------------------
    # Directory validation
    # ---------------------------------------------------------
    for d in dirs:
        rva = d.get("rva")
        size = d.get("size")
        name = d.get("name") or d.get("index")

        if not isinstance(rva, int) or not isinstance(size, int):
            continue

        # 1) Negative values
        if rva < 0 or size < 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_INVALID_RANGE,
                details={"directory": name, "rva": rva, "size": size},
            ))
            continue

        # 2) Empty directory (rva=0, size=0)
        if rva == 0 and size == 0:
            if name in REQUIRED_NONZERO_DIRS:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED,
                    details={"directory": name},
                ))
            continue

        # 3) Zero-RVA + non-zero size → primary anomaly only
        if rva == 0 and size > 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE,
                details={"directory": name, "rva": rva, "size": size},
            ))
            continue

        # 4) Directory in headers
        if isinstance(size_of_headers, int) and rva < size_of_headers:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_IN_HEADERS,
                details={"directory": name, "rva": rva, "size_of_headers": size_of_headers},
            ))

        # 5) Out-of-range
        out_of_range = False
        if rva + size > size_of_image:
            out_of_range = True
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE,
                details={"directory": name, "rva": rva, "size": size, "size_of_image": size_of_image},
            ))

        # Skip mapping if out-of-range
        if out_of_range:
            continue

        # 6) Overlay detection
        if isinstance(overlay_offset, int):
            raw_offset = None
            for va_start, va_end, sec_name in section_ranges:
                if va_start <= rva < va_end:
                    sec = next(s for s in sections if s.get("name") == sec_name)
                    raw_offset = sec.get("raw_address") + (rva - va_start)
                    break

            if isinstance(raw_offset, int) and raw_offset >= overlay_offset:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_IN_OVERLAY,
                    details={"directory": name, "rva": rva, "raw_offset": raw_offset},
                ))

        # 7) Skip mapping if directory lands on a zero-length section
        zero_length_hit = False
        for va_start, va_end, sec_name in section_ranges:
            if va_start == rva and va_start == va_end:
                zero_length_hit = True
                break

        if zero_length_hit:
            continue

        # 8) Section mapping
        mapped_sections = []
        for va_start, va_end, sec_name in section_ranges:
            if rva < va_end and (rva + size) > va_start:
                mapped_sections.append(sec_name)

        if not mapped_sections:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION,
                details={"directory": name, "rva": rva, "size": size},
            ))
        elif len(mapped_sections) > 1:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS,
                details={"directory": name, "sections": mapped_sections},
            ))

    # ---------------------------------------------------------
    # Directory overlap detection
    # ---------------------------------------------------------
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
