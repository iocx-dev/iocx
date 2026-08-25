# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import List, Optional, Tuple

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from iocx.schemas.internal_schema import InternalMetadata
from .decorators import depends_on


def _build_section_ranges(sections: list[dict]) -> list[Tuple[int, int, str]]:
    ranges: list[Tuple[int, int, str]] = []
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        name = sec.get("name")
        if isinstance(va, int) and isinstance(vs, int) and isinstance(name, str):
            ranges.append((va, va + vs, name))
    return ranges


def _map_rva_to_raw(
    rva: int,
    sections: list[dict],
    section_ranges: list[Tuple[int, int, str]],
) -> Optional[Tuple[int, dict]]:
    for va_start, va_end, sec_name in section_ranges:
        if va_start <= rva < va_end:
            sec = next((s for s in sections if s.get("name") == sec_name), None)
            if not sec:
                return None
            base_raw = sec.get("raw_address")
            if not isinstance(base_raw, int):
                return None
            raw_offset = base_raw + (rva - va_start)
            return raw_offset, sec
    return None


@depends_on("internal", "metadata", "analysis")
def validate_load_config_directory(internal: InternalMetadata, metadata: PublicMetadata, analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    opt = metadata.get("optional_header") or {}
    dirs = analysis.get("data_directories") or metadata.get("data_directories") or []
    sections = analysis.get("sections", []) or []
    overlay_offset = analysis.get("overlay_offset")
    load_config = analysis.get("load_config") or {}

    size_of_image = opt.get("size_of_image")
    magic = internal.get("optional_header_magic") # 0x10B (PE32) or 0x20B (PE32+)

    if not isinstance(size_of_image, int):
        return issues

    # ---------------------------------------------------------
    # Locate Load Config directory entry
    # ---------------------------------------------------------
    lcd_dir = None
    for d in dirs:
        name = d.get("name")
        index = d.get("index")
        if name == "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG" or index == 10:
            lcd_dir = d
            break

    if not lcd_dir:
        return issues

    rva = lcd_dir.get("rva")
    size = lcd_dir.get("size")

    if not isinstance(rva, int) or not isinstance(size, int):
        return issues

    if size == 0 or rva == 0:
        # Generic directory validator already flags these; nothing to add here.
        return issues

    # ---------------------------------------------------------
    # Minimum size validation (architecture-dependent)
    # ---------------------------------------------------------
    if magic == 0x20B:
        min_size = 0x70 # PE32+
    else:
        min_size = 0x48 # PE32

    if size < min_size:
        issues.append(StructuralIssue(
            issue=ReasonCodes.LOAD_CONFIG_TOO_SMALL,
            details={
                "rva": rva,
                "size": size,
                "min_size": min_size,
            },
        ))
        # Still continue; parser may have recovered some fields.

    # ---------------------------------------------------------
    # Truncation / parsing completeness
    # ---------------------------------------------------------
    parsed_size = load_config.get("parsed_size")
    if isinstance(parsed_size, int) and parsed_size < min(size, min_size):
        issues.append(StructuralIssue(
            issue=ReasonCodes.LOAD_CONFIG_TRUNCATED,
            details={
                "rva": rva,
                "declared_size": size,
                "parsed_size": parsed_size,
            },
        ))

    # ---------------------------------------------------------
    # Guard CF metadata consistency
    # ---------------------------------------------------------
    g_check = load_config.get("guard_cf_check_function_pointer")
    g_dispatch = load_config.get("guard_cf_dispatch_function_pointer")
    g_table = load_config.get("guard_cf_function_table")
    g_count = load_config.get("guard_cf_function_count")

    guard_values = [
        v for v in (g_check, g_dispatch, g_table, g_count)
        if isinstance(v, int)
    ]

    if guard_values:
        any_nonzero = any(v != 0 for v in guard_values)
        any_zero = any(v == 0 for v in guard_values)
        if any_nonzero and any_zero:
            issues.append(StructuralIssue(
                issue=ReasonCodes.LOAD_CONFIG_GUARD_CF_INCONSISTENT,
                details={
                    "check": g_check,
                    "dispatch": g_dispatch,
                    "table": g_table,
                    "count": g_count,
                },
            ))

    # ---------------------------------------------------------
    # Section mapping helpers
    # ---------------------------------------------------------
    section_ranges = _build_section_ranges(sections)

    # ---------------------------------------------------------
    # Security cookie validation (location + permissions + overlay)
    # ---------------------------------------------------------
    cookie_rva = load_config.get("security_cookie_rva")
    if isinstance(cookie_rva, int) and cookie_rva != 0:
        mapped = _map_rva_to_raw(cookie_rva, sections, section_ranges)
        if not mapped:
            issues.append(StructuralIssue(
                issue=ReasonCodes.LOAD_CONFIG_COOKIE_INVALID,
                details={"cookie_rva": cookie_rva, "sub_reason": "unmapped"},
            ))
        else:
            cookie_raw, sec = mapped
            characteristics = sec.get("characteristics", 0)
            # IMAGE_SCN_MEM_WRITE = 0x80000000
            writable = bool(isinstance(characteristics, int) and (characteristics & 0x80000000))

            if not writable:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.LOAD_CONFIG_COOKIE_INVALID,
                    details={
                        "cookie_rva": cookie_rva,
                        "section": sec.get("name"),
                        "characteristics": characteristics,
                        "sub_reason": "non_writable_section",
                    },
                ))

            if isinstance(overlay_offset, int) and cookie_raw >= overlay_offset:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.LOAD_CONFIG_COOKIE_IN_OVERLAY,
                    details={
                        "cookie_rva": cookie_rva,
                        "cookie_raw": cookie_raw,
                        "overlay_offset": overlay_offset,
                    },
                ))

    # ---------------------------------------------------------
    # SEH table validation
    # ---------------------------------------------------------
    seh_table_rva = load_config.get("seh_table_rva")
    seh_count = load_config.get("seh_count")

    if isinstance(seh_count, int) and seh_count > 0:
        if not isinstance(seh_table_rva, int) or seh_table_rva == 0:
            issues.append(StructuralIssue(
                issue=ReasonCodes.LOAD_CONFIG_SEH_INVALID,
                details={
                    "seh_table_rva": seh_table_rva,
                    "seh_count": seh_count,
                    "sub_reason": "missing_table_rva",
                },
            ))
        else:
            # Basic range check: table must fit in image
            # (each entry is 4 bytes RVA in practice; keep it simple here)
            table_size = seh_count * 4
            if seh_table_rva + table_size > size_of_image:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.LOAD_CONFIG_SEH_INVALID,
                    details={
                        "seh_table_rva": seh_table_rva,
                        "seh_count": seh_count,
                        "size_of_image": size_of_image,
                        "sub_reason": "out_of_range",
                    },
                ))
            else:
                mapped = _map_rva_to_raw(seh_table_rva, sections, section_ranges)
                if not mapped:
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.LOAD_CONFIG_SEH_INVALID,
                        details={
                            "seh_table_rva": seh_table_rva,
                            "seh_count": seh_count,
                            "sub_reason": "unmapped",
                        },
                    ))
                else:
                    seh_raw, _ = mapped
                    if isinstance(overlay_offset, int) and seh_raw >= overlay_offset:
                        issues.append(StructuralIssue(
                            issue=ReasonCodes.LOAD_CONFIG_SEH_INVALID,
                            details={
                                "seh_table_rva": seh_table_rva,
                                "seh_count": seh_count,
                                "seh_raw": seh_raw,
                                "overlay_offset": overlay_offset,
                                "sub_reason": "in_overlay",
                            },
                        ))

    # ---------------------------------------------------------
    # TimeDateStamp / compiler hints are parsed but not strictly validated
    # (we rely on truncation + size checks above to guard them)
    # ---------------------------------------------------------

    return issues
