# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Project public metadata into Detection-shaped output for downstream consumers.

This module does NOT compute new information about the PE; it restructures
the already-extracted public metadata into the Detection format expected by
the CLI and detection consumer API.

The primary additions made here are:
- Derived statistics (counts, entropy ranges)
- Sorted/grouped views (DLLs grouped by name)
- Shape conversion from metadata blocks to Detection records

Anything that decodes raw PE structure (e.g., subsystem names, machine
types, DLL characteristics) belongs in the parser layer (iocx.parsers),
not here. If you find yourself adding decoding logic here, consider whether
it should be in pe_parser / pe_constants instead.
"""

from dataclasses import asdict
from iocx.models import Detection


def analyse_extended(pe, metadata, strings):
    detections = []

    import_details = metadata.get("import_details", [])
    delayed_imports = metadata.get("delayed_imports", [])
    bound_imports = metadata.get("bound_imports", [])
    exports = metadata.get("exports", [])
    resources = metadata.get("resources", [])
    tls = metadata.get("tls")
    signatures = metadata.get("signatures", [])

    #
    # Summary block — derived statistics on the metadata lists
    #
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
    # Grouped imports — group by DLL with sorted function lists
    #
    grouped = {}
    for imp in import_details:
        dll = imp["dll"]
        func = imp["function"]
        ordinal = imp["ordinal"]
        if func is None and ordinal is not None:
            func = f"#{ordinal}"
        grouped.setdefault(dll, []).append(func)

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
    # Delayed imports — same grouping pattern as imports
    # Note: full structural validation of delay-load tables is deferred
    # to a future requirement.
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
    # Bound imports — sorted by DLL name
    #
    if bound_imports:
        detections.append(
            Detection(
                category="pe_metadata",
                value="bound_imports",
                start=0,
                end=0,
                metadata={
                    "entries": sorted(
                        bound_imports,
                        key=lambda x: x["dll"].lower() if x["dll"] else "",
                    )
                },
            )
        )

    #
    # Exports summary
    # Note: this is a metadata view. Structural validity of the export
    # table is reported separately via the validator's reason codes
    # (EXPORT_DIRECTORY_INVALID_HEADER, EXPORT_NAME_RVA_INVALID, etc.).
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
    # Note: depends on the TLS parsing work currently deferred. Current
    # output reflects whatever the existing TLS extraction produces.
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
    # Header — verbatim pass-through. The parser layer now provides
    # subsystem_name and (after the machine decoding move) machine_name.
    #
    header = metadata.get("header", {})
    if header:
        detections.append(
            Detection(
                category="pe_metadata",
                value="header",
                start=0,
                end=0,
                metadata=header,
            )
        )

    #
    # Optional Header — verbatim pass-through. The parser layer provides
    # decoded DLL characteristics flags and sizing data.
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
    # Rich Header — verbatim pass-through.
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
    # Digital Signature — verbatim pass-through with a presence flag.
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
    # Resource summary — derived statistics on the resources list
    #
    if resources:
        types = sorted({r["type"] for r in resources})
        # Resources with computation errors have entropy = None;
        # exclude them from statistics so a single failure doesn't
        # poison the aggregate values.
        valid_entropies = [r["entropy"] for r in resources if r["entropy"] is not None]
        if valid_entropies:
            entropy_stats = {
                "entropy_min": min(valid_entropies),
                "entropy_max": max(valid_entropies),
                "entropy_avg": sum(valid_entropies) / len(valid_entropies),
            }
        else:
            entropy_stats = {
                "entropy_min": None,
                "entropy_max": None,
                "entropy_avg": None,
            }
        detections.append(
            Detection(
                category="pe_metadata",
                value="resources",
                start=0,
                end=0,
                metadata={
                    "count": len(resources),
                    "types": types,
                    **entropy_stats,
                },
            )
        )

    return [asdict(d) for d in detections]
