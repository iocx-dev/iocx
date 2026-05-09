# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Dict, Any, List, Optional
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000


def _map_rva_to_section(sections: List[Dict[str, Any]], rva: int) -> Optional[Dict[str, Any]]:
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if isinstance(va, int) and isinstance(vs, int):
            if va <= rva < va + vs:
                return sec
    return None


def _map_rva_to_file_offset(sections: List[Dict[str, Any]], rva: int) -> Optional[int]:
    """
    Map an RVA to a file offset using section table.
    Returns None if the RVA does not fall into any section or
    if required fields are missing.
    """
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        raw = sec.get("raw_address")
        raw_size = sec.get("raw_size")

        if not (isinstance(va, int) and isinstance(vs, int) and isinstance(raw, int) and isinstance(raw_size, int)):
            continue

        if va <= rva < va + vs:
            # Map RVA into the section's raw range
            delta = rva - va
            if 0 <= delta < raw_size:
                return raw + delta

    return None


@depends_on("metadata", "analysis")
def validate_entrypoint(metadata: PublicMetadata, analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    # --- Extract entrypoint from extended header ---
    header_ext = [
        e for e in analysis.get("extended", [])
        if isinstance(e, dict) and e.get("value") == "header"
    ]
    if not header_ext:
        return issues

    header_meta = header_ext[0].get("metadata") or {}
    ep = header_meta.get("entry_point")
    if not isinstance(ep, int):
        return issues

    # --- Optional header context (for headers / image bounds) ---
    opt = metadata.get("optional_header") or {}
    size_of_headers = opt.get("size_of_headers")
    size_of_image = opt.get("size_of_image")

    # EP obviously bogus (zero or negative)
    if ep <= 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_ZERO_OR_NEGATIVE,
            details={"entry_point": ep},
        ))

    # EP inside headers (if we know SizeOfHeaders)
    if isinstance(size_of_headers, int) and size_of_headers > 0 and ep < size_of_headers:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_HEADERS,
            details={"entry_point": ep, "size_of_headers": size_of_headers},
        ))

    sections = analysis.get("sections", []) or []
    if not sections:
        return issues

    # --- A. EP must map to a valid section ---
    sec = _map_rva_to_section(sections, ep)
    if sec is None:
        # If we know SizeOfImage, make it explicit that EP is within or beyond it
        details: Dict[str, Any] = {"entry_point": ep}
        if isinstance(size_of_image, int) and size_of_image > 0:
            details["size_of_image"] = size_of_image
            if ep >= size_of_image:
                details["position"] = "beyond_size_of_image"
            else:
                details["position"] = "within_size_of_image_but_no_section"
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_OUT_OF_BOUNDS,
            details=details,
        ))
        return issues # cannot continue without a section

    name = (sec.get("name") or "").strip()
    chars = sec.get("characteristics", 0)

    executable = bool(isinstance(chars, int) and (chars & IMAGE_SCN_MEM_EXECUTE))
    has_code = bool(isinstance(chars, int) and (chars & IMAGE_SCN_CNT_CODE))
    discardable = bool(isinstance(chars, int) and (chars & IMAGE_SCN_MEM_DISCARDABLE))

    # --- B. Section must be executable ---
    if not executable:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_SECTION_NOT_EXECUTABLE,
            details={"entry_point": ep, "section": name, "characteristics": chars},
        ))

    # EP in non-code / non-standard section types (resources, relocations, etc.)
    lower_name = name.lower()
    if lower_name in {".rsrc", ".reloc"} or (not has_code and not executable):
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_NON_CODE_SECTION,
            details={"entry_point": ep, "section": name, "characteristics": chars},
        ))

    # EP in discardable section
    if discardable:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_DISCARDABLE_SECTION,
            details={"entry_point": ep, "section": name, "characteristics": chars},
        ))

    # --- C. EP must not fall into truncated or zero-length regions ---
    va = sec.get("virtual_address")
    vs = sec.get("virtual_size")

    if isinstance(vs, int) and vs == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION,
            details={"entry_point": ep, "section": name, "reason": "zero_length_section"},
        ))
    elif isinstance(va, int) and isinstance(vs, int) and ep >= va + vs:
        # Only emit the "beyond_virtual_size" variant if we didn't already flag zero-length
        issues.append(StructuralIssue(
            issue=ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION,
            details={"entry_point": ep, "section": name, "reason": "beyond_virtual_size"},
        ))

    # --- D. EP must not point into overlays (RVA → file offset) ---
    overlay_offset = analysis.get("overlay_offset")
    if isinstance(overlay_offset, int):
        ep_file_offset = _map_rva_to_file_offset(sections, ep)
        if isinstance(ep_file_offset, int) and ep_file_offset >= overlay_offset:
            issues.append(StructuralIssue(
                issue=ReasonCodes.ENTRYPOINT_IN_OVERLAY,
                details={
                    "entry_point": ep,
                    "entry_point_file_offset": ep_file_offset,
                    "overlay_offset": overlay_offset,
                },
            ))

    return issues
