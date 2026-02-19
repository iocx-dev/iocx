import pefile

def _walk_resources(pe, directory, resource_strings):
    for entry in directory.entries:
        if hasattr(entry, "directory"):
            walk_resources(pe, entry.directory, resource_strings)
        elif hasattr(entry, "data"):
            data_rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            data = pe.get_data(data_rva, size)
            resource_strings.extend(extract_strings_from_bytes(data))

def parse_pe(path):
    try:
        # fast_load=True avoids parsing every directory up front, which is ideal for performance and for untrusted files.
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        # Extract imports defensively to avoid crashes on malformed or stripped binaries
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="ignore"))

        # PE section names are fixed‑length, null‑padded byte strings, so stripping nulls is necessary
        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        # Extract strings from resource directory
        resource_strings = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            _walk_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE, resource_strings)

        return {
            "file_type": "PE",
            "imports": imports,
            "sections": sections,
            "resource_strings": resource_strings,
        }

    except Exception:
        return {}
