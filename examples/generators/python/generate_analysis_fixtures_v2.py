# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import os
import struct
from pathlib import Path

FIXTURE_DIR = Path("tests/integration/fixtures/bin/analysis")
FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x400000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_TLS = 9


# ------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------

def align_up(x, a):
    return (x + (a - 1)) & ~(a - 1)


def write_file(path: Path, data: bytes):
    path.write_bytes(data)
    print(f"[+] Wrote {path} ({len(data)} bytes)")


def make_dos_header():
    return (
        b"MZ" +
        b"\x00" * 58 +
        struct.pack("<I", 0x80) # e_lfanew
    )


def make_pe_header(num_sections=1, optional_header_size=0xE0):
    return (
        b"PE\x00\x00" +
        struct.pack("<H", 0x14C) + # Machine (Intel 386)
        struct.pack("<H", num_sections) +
        struct.pack("<I", 0x5E2A5C00) + # TimeDateStamp
        b"\x00" * 8 + # Symbol table
        struct.pack("<H", optional_header_size) +
        struct.pack("<H", 0x010F) # Characteristics (executable, 32‑bit)
    )


def make_optional_header_base():
    # PE32 Optional Header (0xE0 bytes)
    opt = bytearray()

    # Standard fields (28 bytes)
    opt += struct.pack("<H", 0x10B) # Magic
    opt += b"\x00\x00" # Linker version
    opt += struct.pack("<I", 0) # SizeOfCode
    opt += struct.pack("<I", 0) # SizeOfInitializedData
    opt += struct.pack("<I", 0) # SizeOfUninitializedData
    opt += struct.pack("<I", 0) # AddressOfEntryPoint
    opt += struct.pack("<I", 0) # BaseOfCode
    opt += struct.pack("<I", 0) # BaseOfData

    # Windows-specific fields (68 bytes)
    opt += struct.pack("<I", IMAGE_BASE)
    opt += struct.pack("<I", SECTION_ALIGNMENT)
    opt += struct.pack("<I", FILE_ALIGNMENT)
    opt += struct.pack("<H", 0) # Major OS version
    opt += struct.pack("<H", 0) # Minor OS version
    opt += struct.pack("<H", 0) # Major Image version
    opt += struct.pack("<H", 0) # Minor Image version
    opt += struct.pack("<H", 0) # Major Subsystem version
    opt += struct.pack("<H", 0) # Minor Subsystem version
    opt += struct.pack("<I", 0) # Win32VersionValue
    opt += struct.pack("<I", 0) # SizeOfImage (patched later)
    opt += struct.pack("<I", 0) # SizeOfHeaders (patched later)
    opt += struct.pack("<I", 0) # CheckSum
    opt += struct.pack("<H", 2) # Subsystem (GUI)
    opt += struct.pack("<H", 0) # DllCharacteristics
    opt += struct.pack("<I", 0x100000) # SizeOfStackReserve
    opt += struct.pack("<I", 0x1000) # SizeOfStackCommit
    opt += struct.pack("<I", 0x100000) # SizeOfHeapReserve
    opt += struct.pack("<I", 0x1000) # SizeOfHeapCommit
    opt += struct.pack("<I", 0) # LoaderFlags
    opt += struct.pack("<I", 16) # NumberOfRvaAndSizes

    # Data directories (16 × 8 = 128 bytes)
    for _ in range(16):
        opt += struct.pack("<II", 0, 0)

    assert len(opt) == 0xE0
    return opt


def set_optional_header_field(opt, offset, fmt, value):
    struct.pack_into(fmt, opt, offset, value)


def set_data_directory(opt, index, rva, size):
    # Data directories start at offset 96 (0x60) in PE32 optional header
    base = 0x60 + index * 8
    struct.pack_into("<II", opt, base, rva, size)


def make_section_header(name, virt_size, virt_addr,
                        raw_size, raw_ptr, characteristics):
    name = name.encode().ljust(8, b"\x00")
    return (
        name +
        struct.pack("<I", virt_size) +
        struct.pack("<I", virt_addr) +
        struct.pack("<I", raw_size) +
        struct.pack("<I", raw_ptr) +
        b"\x00" * 12 +
        struct.pack("<I", characteristics)
    )


# ------------------------------------------------------------
# Section builders
# ------------------------------------------------------------

def build_text_section():
    # Tiny entry stub: ret
    code = b"\xC3"
    virt_size = len(code)
    raw_size = align_up(len(code), FILE_ALIGNMENT)
    return code, virt_size, raw_size


def build_import_section(idata_rva):
    def hn(s): return b"\x00\x00" + s.encode("ascii") + b"\x00"

    dll_kernel = b"kernel32.dll\x00"
    dll_advapi = b"advapi32.dll\x00"

    hn_CreateFileA = hn("CreateFileA")
    hn_ReadFile = hn("ReadFile")
    hn_WriteFile = hn("WriteFile")
    hn_RegOpenKeyA = hn("RegOpenKeyA")
    hn_RegQueryValueExA = hn("RegQueryValueExA")

    IID_SIZE = 20
    IMAGE_ORDINAL_FLAG32 = 0x80000000

    offset = 0
    def rva(local_off): return idata_rva + local_off

    # Descriptors
    desc_off = offset
    offset += IID_SIZE * 3 # kernel32, advapi32, null

    # INTs
    int_kernel_off = offset; offset += 4 * 5
    int_advapi_off = offset; offset += 4 * 3

    # IATs
    iat_kernel_off = offset; offset += 4 * 5
    iat_advapi_off = offset; offset += 4 * 3

    # Names
    dll_kernel_off = offset; offset += len(dll_kernel)
    dll_advapi_off = offset; offset += len(dll_advapi)

    hn_CreateFileA_off = offset; offset += len(hn_CreateFileA)
    hn_ReadFile_off = offset; offset += len(hn_ReadFile)
    hn_WriteFile_off = offset; offset += len(hn_WriteFile)
    hn_RegOpenKeyA_off = offset; offset += len(hn_RegOpenKeyA)
    hn_RegQueryValueExA_off = offset; offset += len(hn_RegQueryValueExA)

    data = bytearray(offset)

    def write_iid(base_off, oft_rva, name_rva, ft_rva):
        struct.pack_into("<IIIII", data, base_off,
                         oft_rva, 0, 0, name_rva, ft_rva)

    # kernel32 descriptor
    write_iid(
        desc_off,
        rva(int_kernel_off),
        rva(dll_kernel_off),
        rva(iat_kernel_off),
    )
    # advapi32 descriptor
    write_iid(
        desc_off + IID_SIZE,
        rva(int_advapi_off),
        rva(dll_advapi_off),
        rva(iat_advapi_off),
    )
    # third descriptor is zero (terminator)

    def write_thunks(base_off, entries):
        for i, v in enumerate(entries):
            struct.pack_into("<I", data, base_off + 4 * i, v)

    int_kernel_entries = [
        rva(hn_CreateFileA_off),
        rva(hn_ReadFile_off),
        rva(hn_WriteFile_off),
        IMAGE_ORDINAL_FLAG32 | 123,
        0,
    ]
    int_advapi_entries = [
        rva(hn_RegOpenKeyA_off),
        rva(hn_RegQueryValueExA_off),
        0,
    ]

    write_thunks(int_kernel_off, int_kernel_entries)
    write_thunks(int_advapi_off, int_advapi_entries)
    write_thunks(iat_kernel_off, int_kernel_entries)
    write_thunks(iat_advapi_off, int_advapi_entries)

    # Names
    data[dll_kernel_off:dll_kernel_off+len(dll_kernel)] = dll_kernel
    data[dll_advapi_off:dll_advapi_off+len(dll_advapi)] = dll_advapi

    data[hn_CreateFileA_off:hn_CreateFileA_off+len(hn_CreateFileA)] = hn_CreateFileA
    data[hn_ReadFile_off:hn_ReadFile_off+len(hn_ReadFile)] = hn_ReadFile
    data[hn_WriteFile_off:hn_WriteFile_off+len(hn_WriteFile)] = hn_WriteFile
    data[hn_RegOpenKeyA_off:hn_RegOpenKeyA_off+len(hn_RegOpenKeyA)] = hn_RegOpenKeyA
    data[hn_RegQueryValueExA_off:hn_RegQueryValueExA_off+len(hn_RegQueryValueExA)] = hn_RegQueryValueExA

    import_rva = rva(desc_off)
    import_size = offset - desc_off
    return bytes(data), import_rva, import_size, offset


def build_export_section(edata_rva, name="TestExport"):
    # Very small, not fully rich, but structurally valid IMAGE_EXPORT_DIRECTORY
    dll_name = b"testdll.dll\x00"
    func_name = name.encode("ascii") + b"\x00"

    offset = 0
    def rva(local_off): return edata_rva + local_off

    dir_off = offset
    offset += 40 # IMAGE_EXPORT_DIRECTORY

    name_rva_off = offset; offset += len(dll_name)
    func_name_off = offset; offset += len(func_name)

    # Export Address Table (1 function)
    eat_off = offset; offset += 4

    # Name Pointer Table (1)
    name_ptr_off = offset; offset += 4

    # Ordinal Table (1)
    ord_off = offset; offset += 2

    data = bytearray(offset)

    # Directory
    struct.pack_into("<I", data, dir_off + 0x0, 0) # Characteristics
    struct.pack_into("<I", data, dir_off + 0x4, 0) # TimeDateStamp
    struct.pack_into("<H", data, dir_off + 0x8, 0) # MajorVersion
    struct.pack_into("<H", data, dir_off + 0xA, 0) # MinorVersion
    struct.pack_into("<I", data, dir_off + 0xC, rva(name_rva_off)) # Name
    struct.pack_into("<I", data, dir_off + 0x10, 0) # Base
    struct.pack_into("<I", data, dir_off + 0x14, 1) # NumberOfFunctions
    struct.pack_into("<I", data, dir_off + 0x18, 1) # NumberOfNames
    struct.pack_into("<I", data, dir_off + 0x1C, rva(eat_off)) # AddressOfFunctions
    struct.pack_into("<I", data, dir_off + 0x20, rva(name_ptr_off)) # AddressOfNames
    struct.pack_into("<I", data, dir_off + 0x24, rva(ord_off)) # AddressOfNameOrdinals

    # DLL name
    data[name_rva_off:name_rva_off+len(dll_name)] = dll_name
    # Function name
    data[func_name_off:func_name_off+len(func_name)] = func_name

    # EAT: RVA of function (we’ll just point into .text at entry)
    struct.pack_into("<I", data, eat_off, 0x1000) # assume .text at 0x1000

    # Name pointer table
    struct.pack_into("<I", data, name_ptr_off, rva(func_name_off))

    # Ordinal table
    struct.pack_into("<H", data, ord_off, 0)

    export_rva = rva(dir_off)
    export_size = offset - dir_off
    return bytes(data), export_rva, export_size, offset


def build_resource_section(rsrc_rva, blob):
    # For fixtures, we can just treat it as opaque data; directory not strictly needed
    data = bytes(blob)
    return data, rsrc_rva, len(data), len(data)


def build_tls_section(tls_rva, data_bytes):
    # Minimal IMAGE_TLS_DIRECTORY32 with StartAddressOfRawData/EndAddressOfRawData
    offset = 0
    def rva(local_off): return tls_rva + local_off

    dir_off = offset
    offset += 24 # IMAGE_TLS_DIRECTORY32

    raw_off = offset
    offset += len(data_bytes)

    buf = bytearray(offset)

    start = rva(raw_off)
    end = start + len(data_bytes)

    struct.pack_into("<I", buf, dir_off + 0x0, start) # StartAddressOfRawData
    struct.pack_into("<I", buf, dir_off + 0x4, end) # EndAddressOfRawData
    struct.pack_into("<I", buf, dir_off + 0x8, 0) # AddressOfIndex
    struct.pack_into("<I", buf, dir_off + 0xC, 0) # AddressOfCallBacks
    struct.pack_into("<I", buf, dir_off + 0x10, 0) # SizeOfZeroFill
    struct.pack_into("<I", buf, dir_off + 0x14, 0) # Characteristics

    buf[raw_off:raw_off+len(data_bytes)] = data_bytes

    tls_dir_rva = rva(dir_off)
    tls_dir_size = 24
    return bytes(buf), tls_dir_rva, tls_dir_size, offset


# ------------------------------------------------------------
# Generic PE builder
# ------------------------------------------------------------

def build_pe(sections, data_dirs, out_path):
    """
    sections: list of dicts:
      {
        "name": ".text",
        "virt_size": ...,
        "raw_size": ...,
        "characteristics": ...,
        "content": bytes,
      }
    data_dirs: dict of {index: (rva, size)}
    """
    num_sections = len(sections)

    # Layout RVAs and raw pointers
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)

    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)

    size_of_image = align_up(rva, SECTION_ALIGNMENT)
    size_of_headers = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)

    # Build headers
    dos = make_dos_header()
    pe = make_pe_header(num_sections=num_sections, optional_header_size=0xE0)
    opt = make_optional_header_base()

    # Patch standard fields
    text = next(s for s in sections if s["name"] == ".text")
    entry_rva = text["virt_addr"]
    base_of_code = text["virt_addr"]
    size_of_code = align_up(text["virt_size"], SECTION_ALIGNMENT)

    set_optional_header_field(opt, 0x10, "<I", size_of_code) # SizeOfCode
    set_optional_header_field(opt, 0x10 + 4*3, "<I", entry_rva) # AddressOfEntryPoint
    set_optional_header_field(opt, 0x10 + 4*4, "<I", base_of_code) # BaseOfCode
    set_optional_header_field(opt, 0x38, "<I", size_of_image) # SizeOfImage
    set_optional_header_field(opt, 0x3C, "<I", size_of_headers) # SizeOfHeaders

    # Data directories
    for idx, (rva_dir, size_dir) in data_dirs.items():
        set_data_directory(opt, idx, rva_dir, size_dir)

    # Section headers
    sh_list = []
    for s in sections:
        sh = make_section_header(
            s["name"],
            virt_size=s["virt_size"],
            virt_addr=s["virt_addr"],
            raw_size=s["raw_size"],
            raw_ptr=s["raw_ptr"],
            characteristics=s["characteristics"],
        )
        sh_list.append(sh)

    headers = dos
    headers += b"\x00" * (0x80 - len(headers))
    headers += pe + bytes(opt) + b"".join(sh_list)
    headers = headers.ljust(size_of_headers, b"\x00")

    # Body
    file_data = bytearray(headers)
    for s in sections:
        start = s["raw_ptr"]
        end = start + s["raw_size"]
        file_data[start:end] = s["content"].ljust(s["raw_size"], b"\x00")

    write_file(out_path, bytes(file_data))


# ------------------------------------------------------------
# Fixture Generators
# ------------------------------------------------------------

def generate_minimal_pe():
    text_code, text_vs, text_rs = build_text_section()
    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        }
    ]
    data_dirs = {}
    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_minimal.exe")


def generate_pe_with_imports():
    text_code, text_vs, text_rs = build_text_section()

    # .idata
    idata_dummy_rva = SECTION_ALIGNMENT * 2
    idata_bytes, import_rva, import_size, idata_vs = build_import_section(idata_dummy_rva)
    idata_rs = align_up(len(idata_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".idata",
            "virt_size": idata_vs,
            "raw_size": idata_rs,
            "characteristics": 0x40000040,
            "content": idata_bytes,
        },
    ]

    # After layout, import_rva must be adjusted to real .idata RVA
    # We built idata assuming rva=idata_dummy_rva; but build_pe will assign
    # the actual virt_addr. So we rebuild idata with the real RVA.
    # To keep it simple, we do a two‑step: layout once, then rebuild idata.

    # First layout to get real .idata RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_idata_rva = sections[1]["virt_addr"]

    # Rebuild idata with correct RVA
    idata_bytes, import_rva, import_size, idata_vs = build_import_section(real_idata_rva)
    idata_rs = align_up(len(idata_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = idata_vs
    sections[1]["raw_size"] = idata_rs
    sections[1]["content"] = idata_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_IMPORT: (import_rva, import_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_with_imports.exe")


def generate_pe_with_exports():
    text_code, text_vs, text_rs = build_text_section()

    edata_dummy_rva = SECTION_ALIGNMENT * 2
    edata_bytes, export_rva, export_size, edata_vs = build_export_section(edata_dummy_rva)
    edata_rs = align_up(len(edata_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".edata",
            "virt_size": edata_vs,
            "raw_size": edata_rs,
            "characteristics": 0x40000040,
            "content": edata_bytes,
        },
    ]

    # Layout once to get real RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_edata_rva = sections[1]["virt_addr"]

    edata_bytes, export_rva, export_size, edata_vs = build_export_section(real_edata_rva)
    edata_rs = align_up(len(edata_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = edata_vs
    sections[1]["raw_size"] = edata_rs
    sections[1]["content"] = edata_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_EXPORT: (export_rva, export_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_with_exports.dll")


def generate_pe_with_resources():
    text_code, text_vs, text_rs = build_text_section()
    blob = b"\x11\x22\x33\x44" * 50

    rsrc_dummy_rva = SECTION_ALIGNMENT * 2
    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(rsrc_dummy_rva, blob)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".rsrc",
            "virt_size": rsrc_vs,
            "raw_size": rsrc_rs,
            "characteristics": 0x40000040,
            "content": rsrc_bytes,
        },
    ]

    # Layout once to get real RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_rsrc_rva = sections[1]["virt_addr"]

    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(real_rsrc_rva, blob)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = rsrc_vs
    sections[1]["raw_size"] = rsrc_rs
    sections[1]["content"] = rsrc_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_RESOURCE: (rsrc_rva, rsrc_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_with_resources.exe")


def generate_pe_with_tls():
    text_code, text_vs, text_rs = build_text_section()
    tls_payload = b"\xAA" * 64

    tls_dummy_rva = SECTION_ALIGNMENT * 2
    tls_bytes, tls_dir_rva, tls_dir_size, tls_vs = build_tls_section(tls_dummy_rva, tls_payload)
    tls_rs = align_up(len(tls_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".tls",
            "virt_size": tls_vs,
            "raw_size": tls_rs,
            "characteristics": 0xC0000040, # initialized data, read/write
            "content": tls_bytes,
        },
    ]

    # Layout once to get real RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_tls_rva = sections[1]["virt_addr"]

    tls_bytes, tls_dir_rva, tls_dir_size, tls_vs = build_tls_section(real_tls_rva, tls_payload)
    tls_rs = align_up(len(tls_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = tls_vs
    sections[1]["raw_size"] = tls_rs
    sections[1]["content"] = tls_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_TLS: (tls_dir_rva, tls_dir_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_with_tls.exe")


def generate_pe_with_versioninfo():
    # Treat version info as a resource blob in .rsrc
    text_code, text_vs, text_rs = build_text_section()
    version_data = b"\x00\x01\x00\x00VS_VERSION_INFO\x00"

    rsrc_dummy_rva = SECTION_ALIGNMENT * 2
    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(rsrc_dummy_rva, version_data)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".rsrc",
            "virt_size": rsrc_vs,
            "raw_size": rsrc_rs,
            "characteristics": 0x40000040,
            "content": rsrc_bytes,
        },
    ]

    # Layout once to get real RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_rsrc_rva = sections[1]["virt_addr"]

    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(real_rsrc_rva, version_data)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = rsrc_vs
    sections[1]["raw_size"] = rsrc_rs
    sections[1]["content"] = rsrc_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_RESOURCE: (rsrc_rva, rsrc_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_with_versioninfo.exe")


def generate_pe_large_resource():
    text_code, text_vs, text_rs = build_text_section()
    blob = os.urandom(4096)

    rsrc_dummy_rva = SECTION_ALIGNMENT * 2
    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(rsrc_dummy_rva, blob)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)

    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        },
        {
            "name": ".rsrc",
            "virt_size": rsrc_vs,
            "raw_size": rsrc_rs,
            "characteristics": 0x40000040,
            "content": rsrc_bytes,
        },
    ]

    # Layout once to get real RVA
    num_sections = len(sections)
    rva = SECTION_ALIGNMENT
    raw = align_up(0x80 + 0x18 + 0xE0 + num_sections * 40, FILE_ALIGNMENT)
    for s in sections:
        s["virt_addr"] = rva
        s["raw_ptr"] = raw
        rva += align_up(s["virt_size"], SECTION_ALIGNMENT)
        raw += align_up(s["raw_size"], FILE_ALIGNMENT)
    real_rsrc_rva = sections[1]["virt_addr"]

    rsrc_bytes, rsrc_rva, rsrc_size, rsrc_vs = build_resource_section(real_rsrc_rva, blob)
    rsrc_rs = align_up(len(rsrc_bytes), FILE_ALIGNMENT)
    sections[1]["virt_size"] = rsrc_vs
    sections[1]["raw_size"] = rsrc_rs
    sections[1]["content"] = rsrc_bytes

    data_dirs = {
        IMAGE_DIRECTORY_ENTRY_RESOURCE: (rsrc_rva, rsrc_size),
    }

    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_large_resource.exe")


def generate_pe_no_import_table():
    # Valid PE with .text only, no import directory
    generate_minimal_pe() # already does that, but keep separate name if you want
    # If you want a distinct file:
    text_code, text_vs, text_rs = build_text_section()
    sections = [
        {
            "name": ".text",
            "virt_size": text_vs,
            "raw_size": text_rs,
            "characteristics": 0x60000020,
            "content": text_code,
        }
    ]
    data_dirs = {}
    build_pe(sections, data_dirs, FIXTURE_DIR / "pe_no_import_table.exe")


def generate_corrupted_pe():
    write_file(FIXTURE_DIR / "pe_corrupted.exe", b"ThisIsNotAPE")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

if __name__ == "__main__":
    generate_minimal_pe()
    generate_pe_with_imports()
    generate_pe_with_exports()
    generate_pe_with_resources()
    generate_pe_with_tls()
    generate_pe_with_versioninfo()
    generate_pe_large_resource()
    generate_pe_no_import_table()
    generate_corrupted_pe()

    print("\nAll fixtures generated.")
