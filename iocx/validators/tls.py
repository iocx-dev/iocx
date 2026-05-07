from typing import Dict, Any, List, Optional
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def _map_rva_to_section(sections, rva) -> Optional[Dict[str, Any]]:
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if isinstance(va, int) and isinstance(vs, int):
            if va <= rva < va + vs:
                return sec
    return None


def validate_tls(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    tls_entries = [
        e for e in analysis.get("extended", [])
        if isinstance(e, dict) and e.get("value") == "tls_directory"
    ]

    # ---------------------------------------------------------
    # 1) Multiple TLS directories
    # ---------------------------------------------------------
    if len(tls_entries) > 1:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_MULTIPLE_DIRECTORIES,
            details={"count": len(tls_entries)},
        ))

    if not tls_entries:
        return issues

    # Only validate the first directory structurally
    entry = tls_entries[0]
    meta = entry.get("metadata") or {}

    start = meta.get("start_address")
    end = meta.get("end_address")
    callbacks = meta.get("callbacks")

    if not isinstance(start, int) or not isinstance(end, int) or not isinstance(callbacks, int):
        return issues

    sections = analysis.get("sections", []) or []
    overlay_offset = analysis.get("overlay_offset")
    size_of_headers = metadata.get("optional_header", {}).get("size_of_headers")

    # ---------------------------------------------------------
    # 2) Range sanity
    # ---------------------------------------------------------
    if start >= end:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_INVALID_RANGE,
            details={"start_address": start, "end_address": end},
        ))
        return issues

    if start == end:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_ZERO_LENGTH_DIRECTORY,
            details={"start_address": start, "end_address": end},
        ))
        return issues

    # ---------------------------------------------------------
    # 3) Missing callbacks
    # ---------------------------------------------------------
    if callbacks == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACKS_MISSING,
            details={"start_address": start, "end_address": end},
        ))
        return issues

    # ---------------------------------------------------------
    # 4) Callback outside TLS range
    # ---------------------------------------------------------
    if not (start <= callbacks < end):
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_OUTSIDE_RANGE,
            details={"callbacks": callbacks, "start_address": start, "end_address": end},
        ))
        # Do not attempt further mapping - avoid cascading anomalies
        return issues

    # ---------------------------------------------------------
    # 5) Callback mapping
    # ---------------------------------------------------------
    sec = _map_rva_to_section(sections, callbacks)
    if sec is None:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_NOT_MAPPED_TO_SECTION,
            details={"callbacks": callbacks},
        ))
        return issues

    name = sec.get("name")
    chars = sec.get("characteristics", 0)
    executable = bool(chars & 0x20000000)

    if not executable:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION,
            details={"callbacks": callbacks, "section": name},
        ))

    # ---------------------------------------------------------
    # 6) Overlay / header checks
    # ---------------------------------------------------------
    if isinstance(size_of_headers, int) and callbacks < size_of_headers:
        issues.append(StructuralIssue(
            issue=ReasonCodes.TLS_CALLBACK_IN_HEADERS,
            details={"callbacks": callbacks, "size_of_headers": size_of_headers},
        ))

    if isinstance(overlay_offset, int):
        raw = sec.get("raw_address")
        va = sec.get("virtual_address")
        if isinstance(raw, int) and isinstance(va, int):
            raw_offset = raw + (callbacks - va)
            if raw_offset >= overlay_offset:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.TLS_CALLBACK_IN_OVERLAY,
                    details={"callbacks": callbacks, "raw_offset": raw_offset},
                ))

    return issues
