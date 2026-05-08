from typing import Dict, Any


def build_resource_structure(pe) -> Dict[str, Any]:
    """
    Build a structural resource tree suitable for validation.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    # Resource directory entry index (IMAGE_DIRECTORY_ENTRY_RESOURCE = 2)
    res_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
    base_rva = res_dir.VirtualAddress

    root_dir = pe.DIRECTORY_ENTRY_RESOURCE

    def build_directory(node, entry_struct=None) -> Dict[str, Any]:
        """
        node: pefile.ResourceDirData
        entry_struct: the IMAGE_RESOURCE_DIRECTORY_ENTRY struct that pointed to this directory
        """

        # Directory RVA is derived from the entry that referenced it
        if entry_struct:
            # Mask off high bit (0x80000000) which indicates "is directory"
            offset = entry_struct.OffsetToData & 0x7FFFFFFF
            rva = base_rva + offset
        else:
            # Root directory: RVA is simply the base RVA
            rva = base_rva

        # Directory size = 16-byte header + 8 bytes per entry
        size = 16 + 8 * len(node.entries)

        entries = []
        for e in node.entries:
            name = str(e.name) if getattr(e, "name", None) is not None else None
            entry_id = getattr(e, "id", None)

            if hasattr(e, "directory") and e.directory is not None:
                # Subdirectory
                subdir = build_directory(e.directory, e.struct)
                entries.append(
                    {
                        "name": name,
                        "id": entry_id,
                        "is_directory": True,
                        "directory": subdir,
                        "data_rva": None,
                        "data_size": None,
                        "raw_offset": None,
                    }
                )
            else:
                # Data entry
                data = e.data
                d = data.struct
                data_rva = d.OffsetToData
                data_size = d.Size
                raw_offset = pe.get_offset_from_rva(data_rva)

                entries.append(
                    {
                        "name": name,
                        "id": entry_id,
                        "is_directory": False,
                        "directory": None,
                        "data_rva": data_rva,
                        "data_size": data_size,
                        "raw_offset": raw_offset,
                    }
                )

        return {
            "rva": rva,
            "size": size,
            "entries": entries,
        }

    root = build_directory(root_dir)

    # Collect string table entries (RT_STRING = 6)
    string_tables = []
    try:
        RT_STRING = 6
        for type_entry in root_dir.entries:
            if getattr(type_entry, "id", None) == RT_STRING and hasattr(type_entry, "directory"):
                for name_entry in type_entry.directory.entries:
                    if hasattr(name_entry, "directory"):
                        for lang_entry in name_entry.directory.entries:
                            if hasattr(lang_entry, "data"):
                                d = lang_entry.data.struct
                                string_tables.append(
                                    {
                                        "rva": d.OffsetToData,
                                        "size": d.Size,
                                    }
                                )
    except Exception:
        pass

    return {
        "root": root,
        "string_tables": string_tables,
    }
