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
                dll_raw = getattr(entry, "dll", None)
                if isinstance(dll_raw, bytes):
                    dll = dll_raw.decode(errors="ignore")
                elif isinstance(dll_raw, str):
                    dll = dll_raw
                else:
                    dll = None

                if dll:
                    imports.append(dll)

                if hasattr(entry, "imports"):
                    for imp in entry.imports:
                        import_details.append({
                            "dll": dll,
                            "function": imp.name.decode(errors="ignore") if getattr(imp, "name", None) else None,
                            "ordinal": getattr(imp, "ordinal", None),
                        })

        # Delayed imports
        delayed_imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_raw = getattr(entry, "dll", None)
                if isinstance(dll_raw, bytes):
                    dll = dll_raw.decode(errors="ignore")
                elif isinstance(dll_raw, str):
                    dll = dll_raw
                else:
                    dll = None

                if hasattr(entry, "imports"):
                    for imp in entry.imports:
                        delayed_imports.append({
                            "dll": dll,
                            "function": imp.name.decode(errors="ignore") if getattr(imp, "name", None) else None,
                            "ordinal": getattr(imp, "ordinal", None),
                        })

        # Bound imports
        bound_imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                dll_raw = getattr(entry, "name", None) or getattr(entry, "dll", None)
                if isinstance(dll_raw, bytes):
                    dll = dll_raw.decode(errors="ignore")
                elif isinstance(dll_raw, str):
                    dll = dll_raw
                else:
                    dll = None

                ts = getattr(entry.struct, "TimeDateStamp", 0)
                bound_imports.append({"dll": dll, "timestamp": ts})

        # PE section names are fixed‑length, null‑padded byte strings, so stripping nulls is necessary
        sections = []
        for s in getattr(pe, "sections", []):
            name = s.Name
            if isinstance(name, bytes):
                name = name.decode(errors="ignore")
            sections.append(name.strip("\x00"))

        # Resource directory
        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") and hasattr(pe, "get_memory_mapped_image"):
            mm = pe.get_memory_mapped_image() or b""
            for entry in getattr(pe.DIRECTORY_ENTRY_RESOURCE, "entries", []):
                type_id = getattr(entry, "id", None)
                type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))

                if not hasattr(entry, "directory"):
                    continue

                for res in getattr(entry.directory, "entries", []):
                    lang = getattr(res, "id", None)
                    if not hasattr(res, "directory"):
                        continue
                    if not getattr(res.directory, "entries", []):
                        continue

                    data_entry = res.directory.entries[0].data
                    size = data_entry.struct.Size
                    if size <= 0:
                        continue

                    offset = data_entry.struct.OffsetToData

                    if offset < 0 or offset + size > len(mm):
                        continue

                    blob = mm[offset:offset + size]
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
                    "name": exp.name.decode(errors="ignore") if getattr(exp, "name", None) else None,
                    "ordinal": getattr(exp, "ordinal", None),
                    "address": getattr(exp, "address", None),
                    "forwarder": exp.forwarder.decode(errors="ignore") if getattr(exp, "forwarder", None) else None,
                })

        # TLS Directory
        tls = None
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
            tls = {
                "start_address": getattr(tls_struct, "StartAddressOfRawData", 0) or 0,
                "end_address": getattr(tls_struct, "EndAddressOfRawData", 0) or 0,
                "callbacks": getattr(tls_struct, "AddressOfCallBacks", 0) or 0,
            }

        # Digital Signatures (WIN_CERTIFICATE)
        signatures = []
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            for sec in pe.DIRECTORY_ENTRY_SECURITY:
                signatures.append({
                    "address": getattr(sec.struct, "VirtualAddress", 0),
                    "size": getattr(sec.struct, "Size", 0),
                })

        # Optional header fields
        opt = getattr(pe, "OPTIONAL_HEADER", None)
        if opt:
            optional_header = {
                "section_alignment": getattr(opt, "SectionAlignment", 0),
                "file_alignment": getattr(opt, "FileAlignment", 0),
                "size_of_image": getattr(opt, "SizeOfImage", 0),
                "size_of_headers": getattr(opt, "SizeOfHeaders", 0),
                "linker_version": f"{getattr(opt, 'MajorLinkerVersion', 0)}.{getattr(opt, 'MinorLinkerVersion', 0)}",
                "os_version": f"{getattr(opt, 'MajorOperatingSystemVersion', 0)}.{getattr(opt, 'MinorOperatingSystemVersion', 0)}",
                "subsystem_version": f"{getattr(opt, 'MajorSubsystemVersion', 0)}.{getattr(opt, 'MinorSubsystemVersion', 0)}",
            }
        else:
            optional_header = {}

        # Rich header
        try:
            rich_header = pe.parse_rich_header()
        except Exception:
            rich_header = None

        # Header metadata
        fh = getattr(pe, "FILE_HEADER", None)
        header = {
            "entry_point": getattr(opt, "AddressOfEntryPoint", 0) if opt else 0,
            "image_base": getattr(opt, "ImageBase", 0) if opt else 0,
            "subsystem": getattr(opt, "Subsystem", 0) if opt else 0,
            "timestamp": getattr(fh, "TimeDateStamp", 0) if fh else 0,
            "machine": getattr(fh, "Machine", 0) if fh else 0,
            "characteristics": getattr(fh, "Characteristics", 0) if fh else 0,
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

    except pefile.PEFormatError:
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
