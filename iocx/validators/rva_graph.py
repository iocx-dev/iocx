# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Dict, Any, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# No directories are strictly required to be non-zero.
#
# The set is intentionally empty: the DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED
# branch below is therefore unreachable in production and exists so a future
# policy change ("directory X must be present") needs only an entry here.
REQUIRED_NONZERO_DIRS: set[str] = set()


# IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) is special: its VirtualAddress
# field is a FILE OFFSET, not an RVA (the attribute certificate table is
# appended to the file and never mapped into the image). Every check here
# interprets the field as an RVA, so applying them to the security directory
# is a category error and double-counts with the certificate parser /
# signature validator, which own that directory's placement truth (validated
# against file_size, e.g. certificate_offset_past_eof). Exclude it from ALL
# RVA-based checks - both the per-directory loop and the overlap detection.
_SECURITY_DIRECTORY_INDEX = 4
_SECURITY_DIRECTORY_NAME = "IMAGE_DIRECTORY_ENTRY_SECURITY"


def _is_security_directory(d: Dict[str, Any]) -> bool:
    """True for IMAGE_DIRECTORY_ENTRY_SECURITY, by index or name."""
    return (
        d.get("index") == _SECURITY_DIRECTORY_INDEX
        or d.get("name") == _SECURITY_DIRECTORY_NAME
    )



@depends_on("metadata", "analysis")
def validate_rva_graph(metadata, analysis):
    issues = []
    # Directory source: the analysis layer wins, falling back to metadata.
    # Note an EMPTY analysis list is falsy and therefore falls through to
    # metadata as well.
    dirs = analysis.get("data_directories") or metadata.get("data_directories") or []
    opt = metadata.get("optional_header") or {}
    sections = analysis.get("sections", []) or []
    size_of_image = opt.get("size_of_image")
    size_of_headers = opt.get("size_of_headers")
    overlay_offset = analysis.get("overlay_offset")

    if not isinstance(size_of_image, int):
        return issues

    section_ranges = []
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        name = sec.get("name")
        if isinstance(va, int) and isinstance(vs, int):
            section_ranges.append((va, va + vs, name))

    for d in dirs:
        if _is_security_directory(d):
            continue
        rva = d.get("rva")
        size = d.get("size")
        name = d.get("name") or d.get("index")
        if not isinstance(rva, int) or not isinstance(size, int):
            continue
        if rva < 0 or size < 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_INVALID_RANGE,
                details={"directory": name, "rva": rva, "size": size}))
            continue
        if rva == 0 and size == 0:
            if name in REQUIRED_NONZERO_DIRS:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED,
                    details={"directory": name}))
            continue
        if rva == 0 and size > 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE,
                details={"directory": name, "rva": rva, "size": size}))
            continue
        if size == 0 and rva != 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA,
                details={"directory": name, "rva": rva, "size": size}))
            continue
        # Deliberately does NOT short-circuit: a directory can lie inside the
        # headers AND be unmapped / out-of-range, and both are worth reporting.
        if isinstance(size_of_headers, int) and rva < size_of_headers:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_IN_HEADERS,
                details={"directory": name, "rva": rva,
                         "size_of_headers": size_of_headers}))
        out_of_range = False
        if rva + size > size_of_image:
            out_of_range = True
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_OUT_OF_RANGE,
                details={"directory": name, "rva": rva, "size": size,
                         "size_of_image": size_of_image}))
        if out_of_range:
            continue

        if isinstance(overlay_offset, int):
            raw_offset = None
            for va_start, va_end, sec_name in section_ranges:
                if va_start <= rva < va_end:
                    sec = next(s for s in sections if s.get("name") == sec_name)
                    base_raw = sec.get("raw_address")
                    if not isinstance(base_raw, int):
                        break
                    raw_offset = base_raw + (rva - va_start)
                    # NOTE raw_size defaults to 0, so a section without one
                    # has an empty raw range and ANY directory mapping into it
                    # will mismatch. On mismatch we `continue` rather than
                    # break, so a later section covering the same VA can still
                    # resolve raw_offset.
                    sec_raw_start = base_raw
                    sec_raw_end = base_raw + sec.get("raw_size", 0)
                    if not (sec_raw_start <= raw_offset < sec_raw_end):
                        issues.append(StructuralIssue(
                            issue=ReasonCodes.DATA_DIRECTORY_RAW_MISMATCH,
                            details={"directory": name, "rva": rva,
                                     "raw_offset": raw_offset,
                                     "section": sec_name,
                                     "section_raw_start": sec_raw_start,
                                     "section_raw_end": sec_raw_end}))
                        continue
                    break

            # FIXED: guard scoped to the overlay check only
            if raw_offset is not None and raw_offset >= overlay_offset:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_IN_OVERLAY,
                    details={"directory": name, "rva": rva,
                             "raw_offset": raw_offset}))

        # Skip mapping if the directory lands exactly on a zero-length
        # section (va_start == rva and the section has no extent).
        zero_length_hit = False
        for va_start, va_end, sec_name in section_ranges:
            if va_start == rva and va_start == va_end:
                zero_length_hit = True
                break
        if zero_length_hit:
            continue

        # Section mapping (half-open interval: a directory ending exactly at
        # a section start does not count as spanning it).
        mapped_sections = []
        for va_start, va_end, sec_name in section_ranges:
            if rva < va_end and (rva + size) > va_start:
                mapped_sections.append(sec_name)
        if not mapped_sections:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_NOT_MAPPED_TO_SECTION,
                details={"directory": name, "rva": rva, "size": size}))
        elif len(mapped_sections) > 1:
            issues.append(StructuralIssue(
                issue=ReasonCodes.DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS,
                details={"directory": name, "sections": mapped_sections}))

    # ---------------------------------------------------------
    # Directory overlap detection
    #
    # Runs independently of the per-directory loop above: a directory skipped
    # there (e.g. zero size) is still compared here.
    # ---------------------------------------------------------
    for i in range(len(dirs)):
        a = dirs[i]
        if _is_security_directory(a):
            continue
        rva_a = a.get("rva")
        size_a = a.get("size")
        if not isinstance(rva_a, int) or not isinstance(size_a, int):
            continue
        end_a = rva_a + size_a
        for j in range(i + 1, len(dirs)):
            b = dirs[j]
            if _is_security_directory(b):
                continue
            rva_b = b.get("rva")
            size_b = b.get("size")
            if not isinstance(rva_b, int) or not isinstance(size_b, int):
                continue
            end_b = rva_b + size_b
            if max(rva_a, rva_b) < min(end_a, end_b):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.DATA_DIRECTORY_OVERLAP,
                    details={"directory_a": a.get("name") or a.get("index"),
                             "directory_b": b.get("name") or b.get("index")}))
    return issues
