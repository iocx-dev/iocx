from dataclasses import asdict
from iocx.models import Detection

# Optional: translate machine + subsystem for readability
_MACHINE_MAP = {
    0x014c: "x86",
    0x8664: "AMD64",
    0x0200: "IA64",
}

_SUBSYSTEM_MAP = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "EFI ROM",
    16: "Xbox",
}

def analyse_extended(pe, metadata, strings):
    detections = []

    #
    # 1. Summary block
    #
    import_details = metadata.get("import_details", [])
    exports = metadata.get("exports", [])
    resource_strings = metadata.get("resource_strings", [])
    tls = metadata.get("tls")

    detections.append(
        Detection(
            category="pe_metadata",
            value="summary",
            start=0,
            end=0,
            metadata={
                "dll_count": len({imp["dll"] for imp in import_details}),
                "import_count": len(import_details),
                "export_count": len(exports),
                "resource_count": len(resource_strings),
                "has_tls": bool(tls),
            },
        )
    )

    #
    # 2. Grouped imports
    #
    grouped = {}
    for imp in import_details:
        dll = imp["dll"]
        func = imp["function"]
        ordinal = imp["ordinal"]

        # Represent ordinal-only imports as "#123"
        if func is None and ordinal is not None:
            func = f"#{ordinal}"

        grouped.setdefault(dll, []).append(func)

    # Sort DLLs and functions for stable output
    for dll in sorted(grouped.keys(), key=str.lower):
        funcs = sorted(grouped[dll], key=lambda x: (x.startswith("#"), x.lower()))
        detections.append(
            Detection(
                category="pe_metadata",
                value="imports",
                start=0,
                end=0,
                metadata={
                    "dll": dll,
                    "functions": funcs,
                },
            )
        )

    #
    # 3. Exports summary
    #
    export_names = [e["name"] for e in exports if e.get("name")]
    detections.append(
        Detection(
            category="pe_metadata",
            value="exports",
            start=0,
            end=0,
            metadata={
                "count": len(exports),
                "names": sorted(export_names, key=str.lower),
            },
        )
    )

    #
    # 4. TLS directory
    #
    if tls:
        detections.append(
            Detection(
                category="pe_metadata",
                value="tls_directory",
                start=0,
                end=0,
                metadata=tls,
            )
        )

    #
    # 5. Header (with human-friendly translations)
    #
    header = metadata.get("header", {})
    machine = header.get("machine")
    subsystem = header.get("subsystem")

    header_pretty = dict(header)
    header_pretty["machine_human"] = _MACHINE_MAP.get(machine, f"0x{machine:04x}")
    header_pretty["subsystem_human"] = _SUBSYSTEM_MAP.get(subsystem, subsystem)

    detections.append(
        Detection(
            category="pe_metadata",
            value="header",
            start=0,
            end=0,
            metadata=header_pretty,
        )
    )

    #
    # 6. Resource summary
    #
    # If we later store entropy per resource, we can compute min/max/avg here.
    detections.append(
        Detection(
            category="pe_metadata",
            value="resources",
            start=0,
            end=0,
            metadata={
                "count": len(resource_strings),
            },
        )
    )

    #
    # Final JSON‑serialisable output
    #
    return [asdict(d) for d in detections]
