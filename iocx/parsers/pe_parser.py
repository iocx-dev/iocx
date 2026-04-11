import pefile
import math
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


def _entropy(data):
    if not data:
        return 0.0
    occur = [0] * 256
    for x in data:
        occur[x] += 1
    ent = 0.0
    for c in occur:
        if c:
            p = c / len(data)
            ent -= p * math.log2(p)
    return ent


def parse_pe(path):
    try:
        # fast_load=True avoids parsing every directory up front, which is ideal for performance and for untrusted files.
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        # Extract imports defensively to avoid crashes on malformed or stripped binaries
        imports = []
        import_details = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore") if entry.dll else None
                imports.append(dll)
                for imp in entry.imports:
                    import_details.append({
                        "dll": dll,
                        "function": imp.name.decode(errors="ignore") if imp.name else None,
                        "ordinal": imp.ordinal,
                    })

        # Delayed imports
        delayed_imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll = entry.dll.decode(errors="ignore") if entry.dll else None
                for imp in entry.imports:
                    delayed_imports.append({
                        "dll": dll,
                        "function": imp.name.decode(errors="ignore") if imp.name else None,
                        "ordinal": imp.ordinal,
                    })

        # Bound imports
        bound_imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                dll = entry.name.decode(errors="ignore") if entry.name else None
                bound_imports.append({
                    "dll": dll,
                    "timestamp": entry.struct.TimeDateStamp,
                })

        # PE section names are fixed‑length, null‑padded byte strings, so stripping nulls is necessary
        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        # Resource directory
        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_id = entry.id
                type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))

                if not hasattr(entry, "directory"):
                    continue

                for res in entry.directory.entries:
                    lang = res.id
                    if not hasattr(res, "directory"):
                        continue
                    if not res.directory.entries:
                        continue

                    data_entry = res.directory.entries[0].data
                    size = data_entry.struct.Size
                    offset = data_entry.struct.OffsetToData

                    blob = pe.get_memory_mapped_image()[offset:offset + size]
                    ent = _entropy(blob)

                    resources.append({
                        "type": type_name,
                        "language": lang,
                        "size": size,
                        "entropy": ent,
                    })

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
                    "forwarder": exp.forwarder.decode(errors="ignore") if exp.forwarder else None,
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

        # Digital Signatures (WIN_CERTIFICATE)
        signatures = []
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            for sec in pe.DIRECTORY_ENTRY_SECURITY:
                signatures.append({
                    "address": sec.struct.VirtualAddress,
                    "size": sec.struct.Size,
                })

        # Optional header fields
        opt = pe.OPTIONAL_HEADER
        optional_header = {
            "section_alignment": opt.SectionAlignment,
            "file_alignment": opt.FileAlignment,
            "size_of_image": opt.SizeOfImage,
            "size_of_headers": opt.SizeOfHeaders,
            "linker_version": f"{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}",
            "os_version": f"{opt.MajorOperatingSystemVersion}.{opt.MinorOperatingSystemVersion}",
            "subsystem_version": f"{opt.MajorSubsystemVersion}.{opt.MinorSubsystemVersion}",
        }

        # Rich header
        rich_header = pe.parse_rich_header()

        # Header metadata
        header = {
            "entry_point": opt.AddressOfEntryPoint,
            "image_base": opt.ImageBase,
            "subsystem": opt.Subsystem,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "machine": pe.FILE_HEADER.Machine,
            "characteristics": pe.FILE_HEADER.Characteristics,
        }

        # Final metadata dict
        metadata = {
            "file_type": "PE",
            "imports": imports,
            "sections": sections,
            "resources": resources,
            "resource_strings": resource_strings,
            "import_details": import_details,
            "delayed_imports": delayed_imports,
            "bound_imports": bound_imports,
            "exports": exports,
            "tls": tls,
            "header": header,
            "optional_header": optional_header,
            "rich_header": rich_header,
            "signatures": signatures,
            "has_signature": bool(signatures),
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
