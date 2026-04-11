import pefile
from .string_extractor import extract_strings_from_bytes
from ..analysis.obfuscation import _shannon_entropy
from typing import List, Dict, Any

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
                dll = entry.dll.decode(errors="ignore") if entry.dll else None
                imports.append(dll)


        # Full import details
        import_details = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore") if entry.dll else None
                for imp in entry.imports:
                    import_details.append({
                        "dll": dll,
                        "function": imp.name.decode(errors="ignore") if imp.name else None,
                        "ordinal": imp.ordinal,
                    })

        # PE section names are fixed‑length, null‑padded byte strings, so stripping nulls is necessary
        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        # Extract strings from resource directory
        resource_strings = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            _walk_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE, resource_strings)

        # Deduplicate resource strings
        resource_strings = list(dict.fromkeys(resource_strings))


        # Exports
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({
                    "name": exp.name.decode(errors="ignore") if exp.name else None,
                    "ordinal": exp.ordinal,
                    "address": exp.address,
                })


        # TLS Directory
        tls = None
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
            tls = {
                "start_address": tls_struct.StartAddressOfRawData,
                "end_address": tls_struct.EndAddressOfRawData,
                "callbacks": getattr(tls_struct, "AddressOfCallBacks", None),
            }


        # Header metadata
        header = {
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "machine": pe.FILE_HEADER.Machine,
            "characteristics": pe.FILE_HEADER.Characteristics,
        }


        # Final metadata dict
        metadata = {
            "file_type": "PE",
            "imports": imports,
            "sections": sections,
            "resource_strings": resource_strings,
            "import_details": import_details,
            "exports": exports,
            "tls": tls,
            "header": header,
        }

        return pe, metadata

    except Exception:
        return None, {}


def analyse_pe_sections(pe) -> List[Dict[str, Any]]:
    results = []
    for s in pe.sections:
        results.append({
            "name": s.Name.decode(errors="ignore").rstrip("\x00"),
            "raw_size": s.SizeOfRawData,
            "virtual_size": s.Misc_VirtualSize,
            "characteristics": s.Characteristics,
            "entropy": _shannon_entropy(s.get_data() or b""),
        })
    return results
