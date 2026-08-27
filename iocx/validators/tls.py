# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the IMAGE_TLS_DIRECTORY.

v0.7.6 migration: this validator now sources TLS structural truth from the
deterministic ``tls_struct`` produced by parser pe_tls (read from
InternalMetadata), rather than from the pefile-derived ``extended`` marker.
All existing directory/pointer checks and reason codes are preserved; the
multiplicity check still consults ``analysis["extended"]``.

Two axes are validated:

  * The preserved cascade operates on the raw-data range
    (Start/EndAddressOfRawData) and the AddressOfCallBacks POINTER, exactly
    as before, including every early return. Note: struct addresses are
    VAs, so section mapping for the pointer is done in RVA space
    (rva = va - ImageBase). Range comparisons stay in VA space. This fixes a
    latent VA/RVA unit mismatch from the pefile path while keeping the same
    codes and control flow.

  * The new target-array checks operate on the resolved callback array
    (the list of callback target VAs the parser walked), which the pefile
    single-value model could not express. This is where the two new v0.7.6
    codes live, so they do not double-count the pointer-based checks:

      TLS_DIRECTORY_TRUNCATED   - header decode failure or a truncated /
                                  looping callback array (parser tombstones).
      TLS_CALLBACK_RVA_INVALID  - a resolved callback TARGET whose VA cannot
                                  form a valid RVA (below ImageBase) or does
                                  not map to any section.

Preserved reason codes:
  TLS_MULTIPLE_DIRECTORIES
  TLS_ZERO_LENGTH_DIRECTORY
  TLS_INVALID_RANGE
  TLS_CALLBACKS_MISSING
  TLS_CALLBACK_OUTSIDE_RANGE
  TLS_CALLBACK_NOT_MAPPED_TO_SECTION      (pointer -> section)
  TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION
  TLS_CALLBACK_IN_HEADERS
  TLS_CALLBACK_IN_OVERLAY
"""

from typing import Dict, Any, List, Optional

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on

IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Parser top-level error tags that mean the fixed TLS header could not be
# decoded — the directory is unusable and maps to TLS_DIRECTORY_TRUNCATED.
_HEADER_DECODE_ERROR_TAGS = {
    "tls_directory_read_failed",
    "tls_directory_truncated",
    "tls_directory_unpack_failed",
}

# Parser tombstones recorded when the callback array could not be resolved
# to an RVA at all. In these cases the parser returns callbacks=[], so the
# per-target loop below has nothing to walk; without surfacing these tags
# the structural anomaly would be silently dropped. They map to
# TLS_CALLBACK_RVA_INVALID (the callback array is unresolvable).
_CALLBACK_RESOLUTION_ERROR_TAGS = {
    "tls_image_base_unavailable",
    "tls_callbacks_va_below_image_base",
}

# Cap on how many invalid-callback-target issues we raise, so a looping /
# hostile array cannot flood the stream. Count is always in details.
_MAX_CALLBACK_TARGET_ISSUES = 16


def _map_rva_to_section(sections, rva) -> Optional[Dict[str, Any]]:
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if isinstance(va, int) and isinstance(vs, int):
            if va <= rva < va + vs:
                return sec
    return None


@depends_on("internal", "metadata", "analysis")
def validate_tls(internal: InternalMetadata,
                 metadata: PublicMetadata,
                 analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    # ---------------------------------------------------------
    # 1) Multiple TLS directories
    # ---------------------------------------------------------
    tls_entries = [
        e for e in analysis.get("extended", [])
        if isinstance(e, dict) and e.get("value") == "tls_directory"
    ]
    if len(tls_entries) > 1:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_MULTIPLE_DIRECTORIES,
            details={"count": len(tls_entries)},
        ))

    tls = internal.get("tls_struct")
    if tls is None:
        return issues  # no TLS directory — not a defect

    # ---------------------------------------------------------
    # 2) Header decode failure
    # Unrecoverable - the fixed struct could not be read/unpacked.
    # ---------------------------------------------------------
    header_errs = [e for e in (tls.get("errors") or [])
                   if e in _HEADER_DECODE_ERROR_TAGS]
    if header_errs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_DIRECTORY_TRUNCATED,
            details={"sub_reason": "header_decode", "errors": header_errs},
        ))
        return issues

    # ---------------------------------------------------------
    # 3) Callback-array truncation / loop
    # ---------------------------------------------------------
    for tag in tls.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_DIRECTORY_TRUNCATED,
            details={"sub_reason": "callback_array", "region": tag},
        ))

    # ---------------------------------------------------------
    # 4) Resolved callback target validation
    # Independent of the raw-data-range cascade below, so it always runs
    # even when the cascade returns early (e.g. zero-length raw data).
    # ---------------------------------------------------------
    _validate_callback_targets(tls, analysis, issues)

    # ---------------------------------------------------------
    # 5) Preserved cascade on raw-data range + AddressOfCallBacks pointer
    # ---------------------------------------------------------
    start = tls.get("start_address_of_raw_data")   # VA
    end = tls.get("end_address_of_raw_data")       # VA
    ptr = tls.get("address_of_callbacks")          # VA of the callback array
    image_base = tls.get("image_base")

    if not isinstance(start, int) or not isinstance(end, int) or not isinstance(ptr, int):
        return issues

    sections = analysis.get("sections", []) or []
    overlay_offset = analysis.get("overlay_offset")
    size_of_headers = (metadata.get("optional_header") or {}).get("size_of_headers")

    # Range sanity (VA space)
    if start == end:
        # A zero-length raw-data region is only anomalous when the directory
        # carries NO resolved callbacks. A zero-length template alongside a
        # valid callback array is legitimate and common, so we do not flag it
        # (the callback targets were already validated in step 4). Either way
        # the degenerate range makes the pointer cascade below meaningless, so
        # we return here.
        if not (tls.get("callbacks") or []):
            issues.append(StructuralIssue(
                issue=ReasonCodes.TLS_ZERO_LENGTH_DIRECTORY,
                details={"start_address": start, "end_address": end},
            ))
        return issues

    if start > end:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_INVALID_RANGE,
            details={"start_address": start, "end_address": end},
        ))
        return issues

    # Missing callbacks
    if ptr == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACKS_MISSING,
            details={"start_address": start, "end_address": end},
        ))
        return issues

    # Callback pointer outside TLS range (VA space)
    if not (start <= ptr < end):
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_OUTSIDE_RANGE,
            details={"callbacks": ptr, "start_address": start,
                     "end_address": end},
        ))
        return issues

    # Pointer -> section mapping. Struct addresses are VAs; convert to RVA
    # before mapping (sections are RVA-space). If ImageBase is unavailable we
    # cannot convert, so we skip the mapping-dependent checks rather than
    # emit against the wrong unit.
    if not isinstance(image_base, int):
        return issues
    ptr_rva = ptr - image_base

    sec = _map_rva_to_section(sections, ptr_rva)
    if sec is None:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_NOT_MAPPED_TO_SECTION,
            details={"callbacks": ptr, "callbacks_rva": ptr_rva},
        ))
        return issues

    name = sec.get("name")
    chars = sec.get("characteristics", 0)
    executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)

    if not executable:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION,
            details={"callbacks": ptr, "section": name},
        ))

    # Overlay / header checks (RVA space)
    if isinstance(size_of_headers, int) and ptr_rva < size_of_headers:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_IN_HEADERS,
            details={"callbacks": ptr, "callbacks_rva": ptr_rva,
                     "size_of_headers": size_of_headers},
        ))

    if isinstance(overlay_offset, int):
        raw = sec.get("raw_address")
        va = sec.get("virtual_address")
        if isinstance(raw, int) and isinstance(va, int):
            raw_offset = raw + (ptr_rva - va)
            if raw_offset >= overlay_offset:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.TLS_CALLBACK_IN_OVERLAY,
                    details={"callbacks": ptr, "raw_offset": raw_offset},
                ))

    return issues


# =================================================================
# Resolved callback-target validation
# =================================================================

def _validate_callback_targets(tls: Dict[str, Any],
                               analysis: AnalysisDict,
                               issues: List[StructuralIssue]) -> None:
    """
    Flag resolved callback target VAs that cannot form a valid RVA (below
    ImageBase) or do not map to any section. Distinct subject from the
    pointer-based TLS_CALLBACK_NOT_MAPPED_TO_SECTION check above (which maps
    the AddressOfCallBacks pointer, not the individual targets).
    """

    # Surface callback-array resolution tombstones the parser recorded but
    # that would otherwise be dropped (callbacks=[] in these cases). One
    # deterministic issue per distinct tag, in a stable order.
    errors = tls.get("errors") or []
    for tag in sorted(set(errors) & _CALLBACK_RESOLUTION_ERROR_TAGS):
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_RVA_INVALID,
            details={"sub_reason": tag},
        ))

    callbacks = tls.get("callbacks") or []
    if not callbacks:
        return

    image_base = tls.get("image_base")
    sections = analysis.get("sections", []) or []

    if not isinstance(image_base, int):
        # Cannot convert VA -> RVA; the parser records this too. One issue.
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_RVA_INVALID,
            details={"sub_reason": "image_base_unavailable",
                     "callback_count": len(callbacks)},
        ))
        return

    invalid: List[Dict[str, Any]] = []
    for va in callbacks:
        if not isinstance(va, int):
            continue
        rva = va - image_base
        if rva < 0:
            invalid.append({"callback_va": va, "sub_reason": "below_image_base"})
            continue
        if _map_rva_to_section(sections, rva) is None:
            invalid.append({"callback_va": va, "callback_rva": rva,
                            "sub_reason": "not_mapped"})

    if not invalid:
        return

    for item in invalid[:_MAX_CALLBACK_TARGET_ISSUES]:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_RVA_INVALID,
            details={**item, "invalid_callback_count": len(invalid)},
        ))
