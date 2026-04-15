from typing import Any, Dict, List, Optional
from iocx.models import Detection


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
        e for e in analysis["extended"]
        if isinstance(e, dict)
        and e.get("value") == key
        and isinstance(e.get("metadata"), dict)
    ]


def _analyse_packer(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    for sec in analysis["sections"]:
        name = (sec.get("name") or "").lower()

        if "upx" in name:
            out.append(_det("packer_suspected", "packer_section_name", {"section": sec["name"]}))

        entropy = sec.get("entropy")
        raw_size = sec.get("raw_size")

        if isinstance(entropy, (int, float)) and isinstance(raw_size, int):
            if entropy >= HIGH_ENTROPY_THRESHOLD and raw_size >= MIN_PACKED_SECTION_SIZE:
                out.append(_det(
                    "packer_suspected",
                    "high_entropy_section",
                    {
                        "section": sec["name"],
                        "entropy": float(entropy),
                        "raw_size": raw_size,
                    },
                ))

    return out


def _analyse_tls(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    for entry in _get_extended(analysis, "tls_directory"):
        meta = entry["metadata"]
        start = meta.get("start_address")
        end = meta.get("end_address")
        callbacks = meta.get("callbacks")

        if start is None or end is None or callbacks is None:
            continue

        if not (start <= callbacks < end):
            out.append(_det(
                "tls_callback_anomaly",
                "callback_outside_tls_range",
                {
                    "callbacks": callbacks,
                    "start_address": start,
                    "end_address": end,
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

    for sec in analysis["sections"]:
        chars = sec.get("characteristics")
        if not isinstance(chars, int):
            continue

        executable = bool(chars & 0x20000000)
        writable = bool(chars & 0x80000000)

        if executable and writable:
            out.append(_det(
                "anti_debug_heuristic",
                "rwx_section",
                {"section": sec["name"], "characteristics": chars},
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


def _analyse_signature(metadata: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    has_sig = bool(metadata.get("has_signature"))
    sigs = metadata.get("signatures") or []

    if has_sig and not sigs:
        out.append(_det(
            "signature_anomaly",
            "signature_flag_set_but_no_metadata",
        ))

    return out


def analyse_pe_heuristics(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    out.extend(_analyse_packer(metadata, analysis))
    out.extend(_analyse_tls(metadata, analysis))
    out.extend(_analyse_anti_debug(metadata, analysis))
    out.extend(_analyse_import_anomalies(metadata, analysis))
    out.extend(_analyse_signature(metadata))

    return out
