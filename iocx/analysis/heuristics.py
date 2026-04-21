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


def _map_rva_to_section(sections: List[Dict[str, Any]], rva: int) -> Optional[Dict[str, Any]]:
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if not isinstance(va, int) or not isinstance(vs, int):
            continue
        if va <= rva < va + vs:
            return sec
    return None


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


def _analyse_section_overlap(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []
    sections = analysis.get("sections", [])

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
                out.append(
                    _det(
                        "pe_structure_anomaly",
                        "section_overlap",
                        {"section_a": a.get("name"), "section_b": b.get("name")},
                    )
                )

    return out


def _analyse_section_alignment(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    opt = metadata.get("optional_header") or {}
    file_alignment = opt.get("file_alignment")
    if not isinstance(file_alignment, int) or file_alignment <= 0:
        return out

    for sec in analysis.get("sections", []):
        raw_addr = sec.get("raw_address")
        raw_size = sec.get("raw_size")
        if not isinstance(raw_addr, int) or not isinstance(raw_size, int):
            continue

        if raw_addr % file_alignment != 0 or raw_size % file_alignment != 0:
            out.append(
                _det(
                    "pe_structure_anomaly",
                    "section_raw_misaligned",
                    {
                        "section": sec.get("name"),
                        "raw_address": raw_addr,
                        "raw_size": raw_size,
                        "file_alignment": file_alignment,
                    },
                )
            )

    return out


def _analyse_optional_header_consistency(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    opt = metadata.get("optional_header") or {}
    size_of_image = opt.get("size_of_image")
    if not isinstance(size_of_image, int) or size_of_image <= 0:
        return out

    max_end = 0
    for sec in analysis.get("sections", []):
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if not isinstance(va, int) or not isinstance(vs, int):
            continue
        max_end = max(max_end, va + vs)

    if max_end > size_of_image:
        out.append(
            _det(
                "pe_structure_anomaly",
                "optional_header_inconsistent_size",
                {"size_of_image": size_of_image, "max_section_end": max_end},
            )
        )

    return out


def _analyse_entrypoint_mapping(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    header_ext = _get_extended(analysis, "header")
    if not header_ext:
        return out

    ep = header_ext[0]["metadata"].get("entry_point")
    if not isinstance(ep, int):
        return out

    sections = analysis.get("sections", [])
    if not sections:
        return out

    if _map_rva_to_section(sections, ep) is None:
        out.append(
            _det(
                "pe_structure_anomaly",
                "entrypoint_out_of_bounds",
                {"entry_point": ep},
            )
        )

    return out


def _analyse_data_directory_anomalies(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories")
    opt = metadata.get("optional_header") or {}
    size_of_image = opt.get("size_of_image")

    if not isinstance(size_of_image, int) or not isinstance(dirs, list):
        return out

    # Out-of-range and zero/size mismatch
    for d in dirs:
        rva = d.get("rva")
        size = d.get("size")
        name = d.get("name") or d.get("index")
        if not isinstance(rva, int) or not isinstance(size, int):
            continue

        if size > 0 and rva == 0:
            out.append(
                _det(
                    "pe_structure_anomaly",
                    "data_directory_zero_rva_nonzero_size",
                    {"directory": name, "rva": rva, "size": size},
                )
            )

        if rva + size > size_of_image:
            out.append(
                _det(
                    "pe_structure_anomaly",
                    "data_directory_out_of_range",
                    {
                        "directory": name,
                        "rva": rva,
                        "size": size,
                        "size_of_image": size_of_image,
                    },
                )
            )

    # Overlaps
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
                out.append(
                    _det(
                        "pe_structure_anomaly",
                        "data_directory_overlap",
                        {
                            "directory_a": a.get("name") or a.get("index"),
                            "directory_b": b.get("name") or b.get("index"),
                        },
                    )
                )

    return out


def _analyse_import_directory_validity(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    dirs = analysis.get("data_directories") or metadata.get("data_directories")
    sections = analysis.get("sections", [])
    if not isinstance(dirs, list) or not sections:
        return out

    for d in dirs:
        name = (d.get("name") or "").lower()
        idx = d.get("index")
        if name == "import" or idx == 1:
            rva = d.get("rva")
            size = d.get("size")
            if not isinstance(rva, int) or not isinstance(size, int):
                continue

            if _map_rva_to_section(sections, rva) is None:
                out.append(
                    _det(
                        "pe_structure_anomaly",
                        "import_rva_invalid",
                        {"rva": rva, "size": size},
                    )
                )

    return out


def analyse_pe_heuristics(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[Detection]:
    out: List[Detection] = []

    out.extend(_analyse_packer(metadata, analysis))
    out.extend(_analyse_tls(metadata, analysis))
    out.extend(_analyse_anti_debug(metadata, analysis))
    out.extend(_analyse_import_anomalies(metadata, analysis))
    out.extend(_analyse_signature(metadata))

    out.extend(_analyse_section_overlap(metadata, analysis))
    out.extend(_analyse_section_alignment(metadata, analysis))
    out.extend(_analyse_optional_header_consistency(metadata, analysis))
    out.extend(_analyse_entrypoint_mapping(metadata, analysis))
    out.extend(_analyse_data_directory_anomalies(metadata, analysis))
    out.extend(_analyse_import_directory_validity(metadata, analysis))

    return out
