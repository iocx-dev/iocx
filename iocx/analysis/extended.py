# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

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
    # Summary block
    #
    import_details = metadata.get("import_details", [])
    delayed_imports = metadata.get("delayed_imports", [])
    bound_imports = metadata.get("bound_imports", [])
    exports = metadata.get("exports", [])
    resources = metadata.get("resources", [])
    tls = metadata.get("tls")
    signatures = metadata.get("signatures", [])

    detections.append(
        Detection(
            category="pe_metadata",
            value="summary",
            start=0,
            end=0,
            metadata={
                "dll_count": len({imp["dll"] for imp in import_details}),
                "import_count": len(import_details),
                "delayed_import_count": len(delayed_imports),
                "bound_import_count": len(bound_imports),
                "export_count": len(exports),
                "resource_count": len(resources),
                "has_tls": bool(tls),
                "has_signature": bool(signatures),
            },
        )
    )

    #
    # Grouped imports
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
                metadata={"dll": dll, "functions": funcs},
            )
        )

    #
    # Delayed imports
    #
    if delayed_imports:
        grouped_delayed = {}
        for imp in delayed_imports:
            dll = imp["dll"]
            func = imp["function"]
            ordinal = imp["ordinal"]
            if func is None and ordinal is not None:
                func = f"#{ordinal}"
            grouped_delayed.setdefault(dll, []).append(func)

        for dll in sorted(grouped_delayed.keys(), key=str.lower):
            funcs = sorted(grouped_delayed[dll], key=lambda x: (x.startswith("#"), x.lower()))
            detections.append(
                Detection(
                    category="pe_metadata",
                    value="delayed_imports",
                    start=0,
                    end=0,
                    metadata={"dll": dll, "functions": funcs},
                )
            )

    #
    # Bound imports
    #
    if bound_imports:
        detections.append(
            Detection(
                category="pe_metadata",
                value="bound_imports",
                start=0,
                end=0,
                metadata={
                    "entries": sorted(bound_imports, key=lambda x: x["dll"].lower() if x["dll"] else "")
                },
            )
        )

    #
    # Exports summary
    #
    export_names = [e["name"] for e in exports if e.get("name")]
    forwarded = [e for e in exports if e.get("forwarder")]

    detections.append(
        Detection(
            category="pe_metadata",
            value="exports",
            start=0,
            end=0,
            metadata={
                "count": len(exports),
                "names": sorted(export_names, key=str.lower),
                "forwarded": forwarded,
            },
        )
    )

    #
    # TLS directory
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
    # Header (with human-friendly translations)
    #
    header = metadata.get("header", {})
    machine = header.get("machine") or 0
    subsystem = header.get("subsystem") or 0

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
    # Optional Header
    #
    optional_header = metadata.get("optional_header")
    if optional_header:
        detections.append(
            Detection(
                category="pe_metadata",
                value="optional_header",
                start=0,
                end=0,
                metadata=optional_header,
            )
        )

    #
    # Rich Header
    #
    rich_header = metadata.get("rich_header")
    if rich_header:
        detections.append(
            Detection(
                category="pe_metadata",
                value="rich_header",
                start=0,
                end=0,
                metadata=rich_header,
            )
        )

    #
    # Digital Signature
    #
    if signatures:
        detections.append(
            Detection(
                category="pe_metadata",
                value="signature",
                start=0,
                end=0,
                metadata={
                    "has_signature": True,
                    "entries": signatures,
                },
            )
        )

    #
    # Resource summary
    #
    if resources:
        types = sorted({r["type"] for r in resources})
        entropies = [r["entropy"] for r in resources]
        detections.append(
            Detection(
                category="pe_metadata",
                value="resources",
                start=0,
                end=0,
                metadata={
                    "count": len(resources),
                    "types": types,
                    "entropy_min": min(entropies),
                    "entropy_max": max(entropies),
                    "entropy_avg": sum(entropies) / len(entropies),
                },
            )
        )

    return [asdict(d) for d in detections]
