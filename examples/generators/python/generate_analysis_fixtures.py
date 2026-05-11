# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

#!/usr/bin/env python3
"""
Generate synthetic PE fixtures for >=v.0.6.0 IOCX tests.

These files are structurally minimal but valid enough for pefile to parse.
They are NOT executable and contain no real code.
"""

import os
import struct
from pathlib import Path

FIXTURE_DIR = Path("tests/integration/fixtures/bin/analysis")
FIXTURE_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def write_file(path: Path, data: bytes):
    path.write_bytes(data)
    print(f"[+] Wrote {path} ({len(data)} bytes)")


def make_dos_header():
    # Minimal DOS header with e_lfanew pointing to 0x80
    return (
        b"MZ" + # e_magic
        b"\x00" * 58 + # padding
        struct.pack("<I", 0x80) # e_lfanew
    )


def make_pe_header(num_sections=1, optional_header_size=0xE0):
    return (
        b"PE\x00\x00" + # Signature
        struct.pack("<H", 0x14C) + # Machine (Intel 386)
        struct.pack("<H", num_sections) +
        struct.pack("<I", 0x5E2A5C00) + # TimeDateStamp
        b"\x00" * 8 + # Symbol table
        struct.pack("<H", optional_header_size) +
        struct.pack("<H", 0x010F) # Characteristics
    )


def make_optional_header(entry_point=0x1000, image_base=0x400000):
    return (
        struct.pack("<H", 0x10B) + # Magic (PE32)
        b"\x00" * 14 +
        struct.pack("<I", entry_point) +
        b"\x00" * 8 +
        struct.pack("<I", image_base) +
        b"\x00" * 0xB8 # pad to 0xE0
    )


def make_section_header(name, raw_size=0x200, raw_ptr=0x400, virt_size=0x200, virt_addr=0x1000):
    name = name.encode().ljust(8, b"\x00")
    return (
        name +
        struct.pack("<I", virt_size) +
        struct.pack("<I", virt_addr) +
        struct.pack("<I", raw_size) +
        struct.pack("<I", raw_ptr) +
        b"\x00" * 12 +
        struct.pack("<I", 0x60000020) # characteristics (code)
    )


# ------------------------------------------------------------
# Fixture Generators
# ------------------------------------------------------------

def generate_minimal_pe():
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".text") +
        b"\x00" * 0x200
    )
    write_file(FIXTURE_DIR / "pe_minimal_v060.exe", data)


def generate_pe_with_imports():
    # Fake import table (not functional, but parseable)
    import_data = b"kernel32.dll\x00CreateFileA\x00"
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".idata", raw_ptr=0x400, raw_size=len(import_data)) +
        import_data
    )
    write_file(FIXTURE_DIR / "pe_with_imports_v060.exe", data)


def generate_pe_with_exports():
    export_data = b"\x00" * 40 + b"TestExport\x00"
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".edata", raw_ptr=0x400, raw_size=len(export_data)) +
        export_data
    )
    write_file(FIXTURE_DIR / "pe_with_exports_v060.dll", data)


def generate_pe_with_resources():
    resource_data = b"\x11\x22\x33\x44" * 50
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".rsrc", raw_ptr=0x400, raw_size=len(resource_data)) +
        resource_data
    )
    write_file(FIXTURE_DIR / "pe_with_resources_v060.exe", data)


def generate_pe_with_tls():
    tls_data = b"\xAA" * 64
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".tls", raw_ptr=0x400, raw_size=len(tls_data)) +
        tls_data
    )
    write_file(FIXTURE_DIR / "pe_with_tls_v060.exe", data)


def generate_pe_with_versioninfo():
    version_data = b"\x00\x01\x00\x00VS_VERSION_INFO\x00"
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".rsrc", raw_ptr=0x400, raw_size=len(version_data)) +
        version_data
    )
    write_file(FIXTURE_DIR / "pe_with_versioninfo_v060.exe", data)


def generate_pe_large_resource():
    blob = os.urandom(4096)
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".rsrc", raw_ptr=0x400, raw_size=len(blob)) +
        blob
    )
    write_file(FIXTURE_DIR / "pe_large_resource_v060.exe", data)


def generate_pe_no_import_table():
    data = (
        make_dos_header() +
        b"\x00" * (0x80 - 64) +
        make_pe_header() +
        make_optional_header() +
        make_section_header(".text") +
        b"\x90" * 0x200
    )
    write_file(FIXTURE_DIR / "pe_no_import_table_v060.exe", data)


def generate_corrupted_pe():
    write_file(FIXTURE_DIR / "pe_corrupted_v060.exe", b"ThisIsNotAPE")


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
