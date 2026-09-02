# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Structural extraction of the PE resource directory.

Unlike the other PE parsers in this package, this one consumes pefile's
already-parsed ``DIRECTORY_ENTRY_RESOURCE`` tree rather than decoding raw
bytes. The resource tree is recursive and pefile's traversal is well
exercised; re-implementing it is deferred. The consequence is recorded
honestly: a tree pefile refuses to parse yields ``None`` here, and the
validator then has nothing to report.

Never raises. A node or entry that cannot be read is recorded as a
tombstone tag in the containing directory's ``errors`` list and skipped, so
one malformed subtree costs that subtree rather than the whole analysis.

Output contract:
    None - no resource directory present (not an error)
    dict per ResourcesStruct in iocx.schemas.internal_schema.
"""

from typing import Any, Dict, List, Optional

import pefile


def build_resource_structure(pe) -> Optional[Dict[str, Any]]:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    # IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
    try:
        res_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        base_rva = int(res_dir.VirtualAddress)
    except (AttributeError, IndexError, ValueError, TypeError):
        return None

    root_dir = pe.DIRECTORY_ENTRY_RESOURCE

    def build_entry(e) -> Dict[str, Any]:
        """
        Decode one IMAGE_RESOURCE_DIRECTORY_ENTRY. May raise; the caller
        records the failure and skips the entry.
        """
        name = str(e.name) if getattr(e, "name", None) is not None else None
        entry_id = getattr(e, "id", None)

        if getattr(e, "directory", None) is not None:
            return {
                "name": name,
                "id": entry_id,
                "is_directory": True,
                "directory": build_directory(e.directory, e.struct),
                "data_rva": None,
                "data_size": None,
                "raw_offset": None,
            }

        d = e.data.struct
        data_rva = d.OffsetToData
        data_size = d.Size

        # Guarded RVA -> offset: a corrupt RVA must not abort the walk.
        # -1 is the sentinel the validator treats as out-of-bounds via its
        # `data_raw < 0` arm.
        try:
            raw_offset = pe.get_offset_from_rva(data_rva)
        except (pefile.PEFormatError, AttributeError):
            raw_offset = -1

        return {
            "name": name,
            "id": entry_id,
            "is_directory": False,
            "directory": None,
            "data_rva": data_rva,
            "data_size": data_size,
            "raw_offset": raw_offset,
        }

    def build_directory(node, entry_struct=None) -> Dict[str, Any]:
        """
        node: pefile.ResourceDirData
        entry_struct: the IMAGE_RESOURCE_DIRECTORY_ENTRY that pointed here
        """
        if entry_struct is not None:
            # Mask off the high bit (0x80000000) marking "is directory".
            offset = entry_struct.OffsetToData & 0x7FFFFFFF
            rva = base_rva + offset
        else:
            rva = base_rva

        errors: List[str] = []

        # The entry list itself may be missing or unreadable on a malformed
        # tree. Without this guard the whole parse aborts.
        try:
            node_entries = list(node.entries)
        except Exception:
            return {"rva": rva, "size": 16, "entries": [],
                    "errors": ["directory_entries_unavailable"]}

        # Size is derived from the DECLARED entry count, before any entry is
        # skipped, so a partially decodable directory still reports the size
        # its header implies: 16-byte header + 8 bytes per entry.
        size = 16 + 8 * len(node_entries)

        entries: List[Dict[str, Any]] = []
        for e in node_entries:
            try:
                entries.append(build_entry(e))
            except Exception:
                # One unreadable entry costs that entry, not the directory.
                errors.append("entry_decode_failed")
                continue

        return {"rva": rva, "size": size, "entries": entries,
                "errors": errors}

    root = build_directory(root_dir)

    # ---- RT_STRING table collection ----
    # A walk failure and a genuine absence of string resources both leave
    # this list empty, so the failure is recorded explicitly.
    string_tables: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        RT_STRING = 6
        for type_entry in root_dir.entries:
            if getattr(type_entry, "id", None) != RT_STRING:
                continue
            if not hasattr(type_entry, "directory"):
                continue
            for name_entry in type_entry.directory.entries:
                if not hasattr(name_entry, "directory"):
                    continue
                for lang_entry in name_entry.directory.entries:
                    if not hasattr(lang_entry, "data"):
                        continue
                    d = lang_entry.data.struct
                    string_tables.append({"rva": d.OffsetToData,
                                          "size": d.Size})
    except Exception:
        errors.append("string_table_walk_failed")

    return {
        "root": root,
        "string_tables": string_tables,
        "errors": errors,
    }
