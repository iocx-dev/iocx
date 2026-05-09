# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pefile
import math
import base64
from .string_extractor import extract_strings_from_bytes
from ..analysis.obfuscation import _shannon_entropy
from typing import List, Dict, Any
from .language_map import PRIMARY_LANG, SUBLANG, DEFAULT_REGION

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def sanitize_sections(sections):
    """
    Remove internal-only fields from section dictionaries before
    returning them in public output.
    """
    sanitized = []
    for sec in sections:
        # Copy only the fields we want to expose
        clean = {
            k: v for k, v in sec.items()
            if k not in ("raw_address", "virtual_address")
        }
        sanitized.append(clean)
    return sanitized


def sanitize(obj):
    """Recursively convert bytes → hex strings so JSON can serialize."""
    if obj is None:
        return None

    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()

    if isinstance(obj, tuple):
        return tuple(sanitize(x) for x in obj)

    if isinstance(obj, list):
        return [sanitize(x) for x in obj]

    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}

    return obj


def _decode_dll_name(dll_raw) -> str | None:
    if isinstance(dll_raw, bytes):
        return dll_raw.decode(errors="ignore")
    if isinstance(dll_raw, str):
        return dll_raw
    return None


def _safe_file_size(pe) -> int:
    data = getattr(pe, "__data__", None)
    if data is None:
        return 0

    size_attr = getattr(data, "size", None)
    if size_attr is None:
        return 0

    return size_attr() if callable(size_attr) else size_attr


def _walk_resources(pe, directory, resource_strings, max_allowed=None, visited=None):
    if visited is None:
        visited = set()

    if max_allowed is None:
        size = _safe_file_size(pe)
        # 10% of file, capped at 20 MB
        max_allowed = min(size // 10, 20_000_000) if size else 20_000_000

    # Prevent infinite recursion on malformed resource trees
    dir_id = id(directory)
    if dir_id in visited:
        return
    visited.add(dir_id)

    for entry in getattr(directory, "entries", []):
        if hasattr(entry, "directory"):
            _walk_resources(pe, entry.directory, resource_strings, max_allowed, visited)
        elif hasattr(entry, "data"):
            data_rva = getattr(entry.data.struct, "OffsetToData", 0)
            size = getattr(entry.data.struct, "Size", 0)

            if size <= 0 or size > max_allowed:
                continue

            try:
                data = pe.get_data(data_rva, size)
            except Exception:
                # Malformed resources (bad RVA/size) – skip safely
                continue

            resource_strings.extend(extract_strings_from_bytes(data))


def _entropy(data: bytes | None) -> float:
    if not data:
        return 0.0

    occur = [0] * 256
    for x in data:
        occur[x] += 1

    ent = 0.0
    length = len(data)
    for c in occur:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def _decode_langid(langid: int) -> str:
    """Return a human-readable locale string from a Windows LANGID."""
    if not isinstance(langid, int):
        return "unknown"

    if langid < 0x0400:
        return "unknown"

    primary = langid & 0x3FF # low 10 bits
    sublang = (langid >> 10) & 0x3F # high bits

    lang = PRIMARY_LANG.get(primary)
    if not lang:
        return "unknown"

    region = SUBLANG.get(sublang)
    if region:
        return f"{lang}-{region}"

    default_region = DEFAULT_REGION.get(lang)
    if default_region:
        return f"{lang}-{default_region}"

    # If no region known, return just the language
    return lang


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_imports(pe):
    imports: list[str] = []
    import_details: list[dict[str, Any]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports, import_details

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = _decode_dll_name(getattr(entry, "dll", None))

        if dll:
            imports.append(dll)

        if hasattr(entry, "imports"):
            for imp in entry.imports:
                name_raw = getattr(imp, "name", None)
                func_name = name_raw.decode(errors="ignore") if name_raw else None

                import_details.append(
                    {
                        "dll": dll,
                        "function": func_name,
                        "ordinal": getattr(imp, "ordinal", None),
                    }
                )

    return imports, import_details


def _parse_delayed_imports(pe):
    delayed_imports: list[dict[str, Any]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        return delayed_imports

    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll = _decode_dll_name(getattr(entry, "dll", None))

        if hasattr(entry, "imports"):
            for imp in entry.imports:
                name_raw = getattr(imp, "name", None)
                func_name = name_raw.decode(errors="ignore") if name_raw else None

                delayed_imports.append(
                    {
                        "dll": dll,
                        "function": func_name,
                        "ordinal": getattr(imp, "ordinal", None),
                    }
                )

    return delayed_imports


def _parse_bound_imports(pe):
    bound_imports: list[dict[str, Any]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
        return bound_imports

    for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
        dll_raw = getattr(entry, "name", None) or getattr(entry, "dll", None)
        dll = _decode_dll_name(dll_raw)

        struct = getattr(entry, "struct", None)
        ts = getattr(struct, "TimeDateStamp", 0) if struct else 0

        bound_imports.append({"dll": dll, "timestamp": ts})

    return bound_imports


def _parse_sections(pe):
    sections: list[dict[str, Any]] = []

    for s in getattr(pe, "sections", []):
        name_raw = getattr(s, "Name", b"")
        name = name_raw.decode(errors="ignore").rstrip("\x00")

        raw_size = getattr(s, "SizeOfRawData", 0)
        virt_size = getattr(s, "Misc_VirtualSize", 0)
        chars = getattr(s, "Characteristics", 0)

        raw_addr = getattr(s, "PointerToRawData", 0)
        virt_addr = getattr(s, "VirtualAddress", 0)

        try:
            data = s.get_data() or b""
        except Exception:
            data = b""

        sections.append(
            {
                "name": name,
                "raw_size": raw_size,
                "virtual_size": virt_size,
                "characteristics": chars,
                "entropy": _entropy(data),
                "raw_address": int(raw_addr),
                "virtual_address": int(virt_addr),
            }
        )

    return sections


def _parse_exports(pe):
    exports: list[dict[str, Any]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name_raw = getattr(exp, "name", None)
        name = name_raw.decode(errors="ignore") if name_raw else None

        fwd_raw = getattr(exp, "forwarder", None)
        forwarder = fwd_raw.decode(errors="ignore") if fwd_raw else None

        exports.append(
            {
                "name": name,
                "ordinal": getattr(exp, "ordinal", None),
                "address": getattr(exp, "address", None),
                "forwarder": forwarder,
            }
        )

    return exports


def _parse_tls(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return None

    tls_dir = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    tls_struct = getattr(tls_dir, "struct", None)
    if not tls_struct:
        return None

    return {
        "start_address": getattr(tls_struct, "StartAddressOfRawData", 0) or 0,
        "end_address": getattr(tls_struct, "EndAddressOfRawData", 0) or 0,
        "callbacks": getattr(tls_struct, "AddressOfCallBacks", 0) or 0,
    }


def _parse_signatures(pe):
    signatures: list[dict[str, Any]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        return signatures

    for sec in pe.DIRECTORY_ENTRY_SECURITY:
        struct = getattr(sec, "struct", None)
        if not struct:
            continue

        signatures.append(
            {
                "address": getattr(struct, "VirtualAddress", 0),
                "size": getattr(struct, "Size", 0),
            }
        )

    return signatures


def _parse_optional_header(pe):
    opt = getattr(pe, "OPTIONAL_HEADER", None)
    if not opt:
        return opt, {}

    optional_header = {
        "section_alignment": getattr(opt, "SectionAlignment", 0),
        "file_alignment": getattr(opt, "FileAlignment", 0),
        "size_of_image": getattr(opt, "SizeOfImage", 0),
        "size_of_headers": getattr(opt, "SizeOfHeaders", 0),
        "linker_version": f"{getattr(opt, 'MajorLinkerVersion', 0)}."
                          f"{getattr(opt, 'MinorLinkerVersion', 0)}",
        "os_version": f"{getattr(opt, 'MajorOperatingSystemVersion', 0)}."
                      f"{getattr(opt, 'MinorOperatingSystemVersion', 0)}",
        "subsystem_version": f"{getattr(opt, 'MajorSubsystemVersion', 0)}."
                             f"{getattr(opt, 'MinorSubsystemVersion', 0)}",
    }

    return opt, optional_header


def _parse_header(pe, opt):
    fh = getattr(pe, "FILE_HEADER", None)

    return {
        "entry_point": getattr(opt, "AddressOfEntryPoint", 0) if opt else 0,
        "image_base": getattr(opt, "ImageBase", 0) if opt else 0,
        "subsystem": getattr(opt, "Subsystem", 0) if opt else 0,
        "timestamp": getattr(fh, "TimeDateStamp", 0) if fh else 0,
        "machine": getattr(fh, "Machine", 0) if fh else 0,
        "characteristics": getattr(fh, "Characteristics", 0) if fh else 0,
    }


def _parse_resources(pe):
    resources: list[dict[str, Any]] = []
    resource_strings: list[str] = []

    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return resources, resource_strings

    # Walk the tree and collect resource_strings
    _walk_resources(pe, root, resource_strings)

    # Extract structured resource entries
    if not hasattr(pe, "get_memory_mapped_image"):
        return resources, resource_strings

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
                "language_name": _decode_langid(lang),
                "size": size,
                "entropy": ent,
            })

    return resources, resource_strings


def _parse_data_directories(pe):
    dirs: list[dict[str, Any]] = []
    opt = getattr(pe, "OPTIONAL_HEADER", None)
    if not opt:
        return dirs

    for idx, dd in enumerate(getattr(opt, "DATA_DIRECTORY", [])):
        name = getattr(dd, "name", None)
        rva = getattr(dd, "VirtualAddress", 0)
        size = getattr(dd, "Size", 0)

        dirs.append(
            {
                "index": idx,
                "name": name,
                "rva": int(rva),
                "size": int(size),
            }
        )

    return dirs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_pe(path):
    try:
        # fast_load=True avoids parsing every directory up front, which is ideal
        # for performance and for untrusted files.
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        imports, import_details = _parse_imports(pe)
        delayed_imports = _parse_delayed_imports(pe)
        bound_imports = _parse_bound_imports(pe)
        sections = _parse_sections(pe)
        sections_list = [s["name"] for s in sections]
        exports = _parse_exports(pe)
        tls = _parse_tls(pe)
        signatures = _parse_signatures(pe)
        opt, optional_header = _parse_optional_header(pe)
        header = _parse_header(pe, opt)
        resources, resource_strings = _parse_resources(pe)

        # Rich header
        try:
            raw_rich_header = pe.parse_rich_header()
        except Exception:
            raw_rich_header = None

        rich_header = sanitize(raw_rich_header)

        metadata = {
            "file_type": "PE",
            "imports": imports,
            "sections": sections_list,
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
    return _parse_sections(pe)

def analyse_data_directories(pe) -> List[Dict[str, Any]]:
    return _parse_data_directories(pe)
