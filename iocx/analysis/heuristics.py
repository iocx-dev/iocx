from typing import Any, Dict, List, Optional
from iocx.models import Detection
from iocx.reason_codes import ReasonCodes

# Thresholds
HIGH_ENTROPY_THRESHOLD = 7.5
MIN_PACKED_SECTION_SIZE = 1024
LARGE_IMPORT_TABLE_THRESHOLD = 500
ORDINAL_ONLY_RATIO_THRESHOLD = 0.5

ANTI_DEBUG_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "DebugBreak",
    "DebugActiveProcess",
    "DebugActiveProcessStop",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtQuerySystemInformation",
    "ZwQueryInformationProcess",
    "ZwSetInformationThread",
}

TIMING_APIS = {
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "timeGetTime",
}

UNCOMMON_DLLS = {
    "ntoskrnl.exe",
    "win32k.sys",
    "hal.dll",
}

_SKIP_ENTROPY = {
    ReasonCodes.ENTROPY_HIGH_SECTION,
    ReasonCodes.ENTROPY_HIGH_OVERLAY,
    ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS,
}


def _det(value: str, reason: str, metadata: Optional[Dict[str, Any]] = None) -> Detection:
    return Detection(
        value=value,
        start=0,
        end=0,
        category="pe_heuristic",
        metadata={"reason": reason, **(metadata or {})},
    )


def _get_extended(analysis: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    return [
        e for e in analysis.get("extended", [])
        if isinstance(e, dict)
        and e.get("value") == key
        and isinstance(e.get("metadata"), dict)
    ]


def _analyse_packer(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    for sec in analysis.get("sections", []):
        name = (sec.get("name") or "").lower()

        if "upx" in name:
            out.append(_det(
                "packer_suspected",
                "packer_section_name",
                {"section": sec.get("name")},
            ))

        entropy = sec.get("entropy")
        raw_size = sec.get("raw_size")

        if isinstance(entropy, (int, float)) and isinstance(raw_size, int):
            if entropy >= HIGH_ENTROPY_THRESHOLD and raw_size >= MIN_PACKED_SECTION_SIZE:
                out.append(_det(
                    "packer_suspected",
                    "high_entropy_section",
                    {
                        "section": sec.get("name"),
                        "entropy": float(entropy),
                        "raw_size": raw_size,
                    },
                ))

    return out


def _analyse_anti_debug(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    for imp in metadata.get("import_details", []):
        func = imp.get("function")
        dll = (imp.get("dll") or "").lower()

        if func in ANTI_DEBUG_APIS:
            out.append(_det(
                "anti_debug_heuristic",
                "anti_debug_api_import",
                {"dll": dll, "function": func},
            ))

        if func in TIMING_APIS:
            out.append(_det(
                "anti_debug_heuristic",
                "timing_api_import",
                {"dll": dll, "function": func},
            ))

    # RWX sections are now structurally validated, but still interesting for anti-debug
    for sec in analysis.get("sections", []):
        chars = sec.get("characteristics")
        if not isinstance(chars, int):
            continue

        executable = bool(chars & 0x20000000)
        writable = bool(chars & 0x80000000)

        if executable and writable:
            out.append(_det(
                "anti_debug_heuristic",
                "rwx_section",
                {"section": sec.get("name"), "characteristics": chars},
            ))

    return out


def _analyse_import_anomalies(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    import_details = metadata.get("import_details", [])
    total = len(import_details)

    if total > LARGE_IMPORT_TABLE_THRESHOLD:
        out.append(_det(
            "import_anomaly",
            "large_import_table",
            {"count": total},
        ))

    ordinal_only = sum(
        1 for imp in import_details
        if imp.get("ordinal") is not None and not imp.get("function")
    )

    if total > 0:
        ratio = ordinal_only / total
        if ratio >= ORDINAL_ONLY_RATIO_THRESHOLD:
            out.append(_det(
                "import_anomaly",
                "high_ordinal_import_ratio",
                {"ordinal_ratio": ratio, "total_imports": total},
            ))

    header = _get_extended(analysis, "header")
    if header:
        subsystem = header[0]["metadata"].get("subsystem_human")
        if subsystem and "GUI" in subsystem:
            for imp in import_details:
                dll = (imp.get("dll") or "").lower()
                if dll in UNCOMMON_DLLS:
                    out.append(_det(
                        "import_anomaly",
                        "uncommon_dll_for_gui_subsystem",
                        {"dll": dll, "subsystem": subsystem},
                    ))

    return out


def _analyse_structural(analysis: Dict[str, Any]) -> List[Detection]:
    """
    Interpret structural validator output from analysis["structural"] and
    surface it as pe_structure_anomaly detections.
    """
    out: List[Detection] = []

    structural = analysis.get("structural") or {}
    if not isinstance(structural, dict):
        return out

    for category, issues in structural.items():
        if not isinstance(issues, list):
            continue

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            reason = issue.get("issue")
            details = issue.get("details") or {}

            if reason in _SKIP_ENTROPY:
                continue

            metadata = {**details}

            out.append(_det(
                "pe_structure_anomaly",
                reason or "unknown_structural_issue",
                metadata,
            ))

    return out


def analyse_pe_heuristics(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    # Behavioural / semantic heuristics
    out.extend(_analyse_packer(metadata, analysis))
    out.extend(_analyse_anti_debug(metadata, analysis))
    out.extend(_analyse_import_anomalies(metadata, analysis))

    # Structural anomalies
    out.extend(_analyse_structural(analysis))

    return out
