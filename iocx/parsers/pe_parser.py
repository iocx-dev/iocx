import pefile
from .string_extractor import extract_strings_from_bytes

def _walk_resources(pe, directory, resource_strings, max_allowed=None, visited=None):
    if visited is None:
        visited = set()

    if max_allowed is None:
        size_attr = pe.__data__.size
        # Support both pefile.PE (size is a method) and test fakes (size is an int)
        size = size_attr() if callable(size_attr) else size_attr
        max_allowed = min(size // 10, 20_000_000) # 10 % of file, capped at 20 MB

    # Prevent infinite recursion on malformed resource trees
    dir_id = id(directory)
    if dir_id in visited:
        return
    visited.add(dir_id)

    for entry in directory.entries:
        if hasattr(entry, "directory"):
            _walk_resources(pe, entry.directory, resource_strings, max_allowed, visited)
        elif hasattr(entry, "data"):
            data_rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            if size <= max_allowed:
                try:
                    data = pe.get_data(data_rva, size) # Some malformed resources have invalid RVAs or sizes so handle exceptions
                except Exception:
                    continue

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
        section_names = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        section_analysis = []
        for s in pe.sections:
            name = s.Name.decode(errors="ignore").strip("\x00")
            raw_size = s.SizeOfRawData
            virt_size = s.Misc_VirtualSize
            characteristics = s.Characteristics

            # Safe entropy calculation
            try:
                sec_data = s.get_data()
                entropy = s.get_entropy()
            except Exception:
                entropy = None

            section_analysis.append({
                "name": name,
                "raw_size": raw_size,
                "virtual_size": virt_size,
                "characteristics": characteristics,
                "entropy": entropy,
            })

        # Extract strings from resource directory
        resource_strings = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            _walk_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE, resource_strings)

        # Deduplicate resource strings
        resource_strings = list(dict.fromkeys(resource_strings))

        return {
            "file_type": "PE",
            "imports": imports,
            "sections": section_names,
            "section_analysis": section_analysis,
            "resource_strings": resource_strings,
        }

    except pefile.PEFormatError:
        return {}
