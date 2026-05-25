# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from iocx.schemas.internal_schema import InternalMetadata
from .decorators import depends_on


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


# ---------------------------------------------------------------------------
# Design Note: Why This Validator Uses Raw Data Directories
#
# The PE Optional Header contains:
# • A fixed 16‑entry data‑directory table (always present in the file)
# • A field NumberOfRvaAndSizes declaring how many entries are *valid*
#
# In well‑formed binaries these two agree, but adversarial binaries can:
# – Declare too few directories (hiding real ones)
# – Declare too many (>16)
# – Declare a count inconsistent with the actual non‑zero entries
#
# Because of this, the OPTIONAL HEADER validator is the ONLY component that
# must inspect the *raw* 16‑entry table (internal.data_directories_raw).
# Its job is to detect header lies, mismatches, and abuse of
# NumberOfRvaAndSizes.
#
# All other validators (rva_graph, load_config, imports, exports, TLS, etc.)
# operate strictly on the *declared* directory list produced by pefile
# (analysis.data_directories), because that list reflects how Windows
# interprets the file. Undeclared directories are undefined by spec and must
# not be validated.
#
# Summary:
# – Raw table → detect header inconsistencies.
# – Declared list → validate PE semantics.
#
# Do NOT use the raw table outside this validator.
# ---------------------------------------------------------------------------
@depends_on("internal", "metadata", "analysis")
def validate_optional_header(internalMetadata: InternalMetadata, metadata: PublicMetadata, analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    opt = metadata.get("optional_header") or {}
    sections = analysis.get("sections", []) or []
    data_directories_raw = internalMetadata.get("data_directories_raw", []) or []
    actual_data_directories = sum(
        1 for d in data_directories_raw
        if d.get("rva", 0) or d.get("size", 0)
    )

    # Extract fields
    size_of_image = opt.get("size_of_image")
    size_of_headers = opt.get("size_of_headers")
    section_alignment = opt.get("section_alignment")
    file_alignment = opt.get("file_alignment")
    size_of_code = opt.get("size_of_code")
    size_of_init = opt.get("size_of_initialized_data")
    size_of_uninit = opt.get("size_of_uninitialized_data")
    image_base = opt.get("image_base")
    num_dirs = internalMetadata.get("number_of_rva_and_sizes")

    # ---------------------------------------------------------
    # 1) SizeOfImage vs max section end
    # ---------------------------------------------------------
    if isinstance(size_of_image, int) and size_of_image > 0:
        max_end = 0
        for sec in sections:
            va = sec.get("virtual_address")
            vs = sec.get("virtual_size")
            if isinstance(va, int) and isinstance(vs, int):
                max_end = max(max_end, va + vs)

        if max_end > size_of_image:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INCONSISTENT_SIZE,
                details={"size_of_image": size_of_image, "max_section_end": max_end},
            ))

    # ---------------------------------------------------------
    # 2) SizeOfHeaders checks
    # ---------------------------------------------------------
    if isinstance(size_of_headers, int) and isinstance(file_alignment, int) and file_alignment > 0:
        # Must be aligned to FileAlignment
        if size_of_headers % file_alignment != 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS,
                details={"size_of_headers": size_of_headers, "file_alignment": file_alignment},
            ))

        # Must be >= end of headers + section table
        # Compute minimal header size: DOS + PE + COFF + optional + section table
        header_end = metadata.get("header_end") # Provided by parser if available
        if isinstance(header_end, int) and size_of_headers < header_end:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS,
                details={"size_of_headers": size_of_headers, "required_minimum": header_end},
            ))

    # ---------------------------------------------------------
    # 3) SectionAlignment checks
    # ---------------------------------------------------------
    if isinstance(section_alignment, int) and isinstance(file_alignment, int):
        if section_alignment < file_alignment:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                details={"section_alignment": section_alignment, "file_alignment": file_alignment},
            ))

        if not _is_power_of_two(section_alignment):
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                details={"section_alignment": section_alignment, "reason": "not_power_of_two"},
            ))

    # ---------------------------------------------------------
    # 4) FileAlignment checks
    # ---------------------------------------------------------
    if isinstance(file_alignment, int):
        if not _is_power_of_two(file_alignment):
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                details={"file_alignment": file_alignment, "reason": "not_power_of_two"},
            ))

        # Microsoft recommends 512–64K
        if file_alignment < 512 or file_alignment > 65536:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                details={"file_alignment": file_alignment, "reason": "out_of_range"},
            ))

    # ---------------------------------------------------------
    # 5) SizeOfCode / SizeOfInitializedData / SizeOfUninitializedData consistency
    # ---------------------------------------------------------
    if isinstance(size_of_code, int) and isinstance(size_of_init, int) and isinstance(size_of_uninit, int):
        total_code = 0
        total_init = 0
        total_uninit = 0

        for sec in sections:
            chars = sec.get("characteristics", 0)
            raw = sec.get("raw_size") or 0
            vs = sec.get("virtual_size") or 0

            if chars & 0x20: # CNT_CODE
                total_code += raw

            if chars & 0x40: # CNT_INITIALIZED_DATA
                total_init += raw

            if chars & 0x80: # CNT_UNINITIALIZED_DATA
                total_uninit += vs

        if size_of_code < total_code or size_of_init < total_init or size_of_uninit < total_uninit:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_SIZE_FIELDS_INCONSISTENT,
                details={
                    "size_of_code": size_of_code,
                    "computed_code": total_code,
                    "size_of_initialized_data": size_of_init,
                    "computed_initialized": total_init,
                    "size_of_uninitialized_data": size_of_uninit,
                    "computed_uninitialized": total_uninit,
                },
            ))

    # ---------------------------------------------------------
    # 6) ImageBase alignment (must be 64K aligned)
    # ---------------------------------------------------------
    if isinstance(image_base, int):
        if image_base % 0x10000 != 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED,
                details={"image_base": image_base},
            ))

    # ---------------------------------------------------------
    # 7) NumberOfRvaAndSizes checks
    # ---------------------------------------------------------
    if isinstance(num_dirs, int):
        if num_dirs < 0 or num_dirs > 16:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES,
                details={"number_of_rva_and_sizes": num_dirs},
            ))

        # Ensure it covers all directories actually present
        dirs = actual_data_directories
        if dirs > num_dirs:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES,
                details={"number_of_rva_and_sizes": num_dirs, "actual_directories": dirs},
            ))

    # ---------------------------------------------------------
    # 8) SizeOfImage alignment
    # ---------------------------------------------------------
    if isinstance(size_of_image, int) and isinstance(section_alignment, int) and section_alignment > 0:
        if size_of_image % section_alignment != 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED,
                details={"size_of_image": size_of_image, "section_alignment": section_alignment},
            ))

    return issues
