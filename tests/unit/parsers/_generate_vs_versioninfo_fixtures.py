# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0
"""
Byte-level VS_VERSIONINFO blob builder for parser stress tests.

A resource compiler will only ever emit well-formed version-info, so the
malformed cases cannot come from a C fixture. This builds the structure
directly, with each mutation expressed as a named, single-fault deviation
from a known-good baseline.
"""

import struct

_VS_FFI_SIGNATURE = 0xFEEF04BD
_VS_FFI_STRUCT_VERSION = 0x00010000


def _u16(v):
    return struct.pack("<H", v & 0xFFFF)


def _sz(text):
    """UTF-16LE, NUL-terminated."""
    return text.encode("utf-16-le") + b"\x00\x00"


def _pad4(buf):
    return buf + b"\x00" * (-len(buf) % 4)


def _node(key, value=b"", children=b"", w_type=0,
          value_length=None, length_override=None):
    """
    Build one VS_VERSIONINFO-family node.

    wLength covers the whole node including children but excluding any
    trailing pad. `value_length` and `length_override` exist so a single
    field can be corrupted without disturbing anything else.
    """
    head = _pad4(_u16(0) + _u16(0) + _u16(w_type) + _sz(key))
    body = _pad4(value) if children else value
    total = len(head) + len(body) + len(children)

    declared_len = total if length_override is None else length_override
    declared_vlen = len(value) if value_length is None else value_length

    return (_u16(declared_len) + _u16(declared_vlen) + _u16(w_type)
            + head[6:] + body + children)


def fixed_file_info(signature=_VS_FFI_SIGNATURE,
                    struct_version=_VS_FFI_STRUCT_VERSION,
                    file_version=(0x000A0000, 0x65F42308),
                    product_version=(0x000A0000, 0x65F42308)):
    """52-byte VS_FIXEDFILEINFO."""
    return struct.pack(
        "<13I",
        signature, struct_version,
        file_version[0], file_version[1],
        product_version[0], product_version[1],
        0x3F, 0x00,        # flags mask, flags
        0x04,              # VOS_NT_WINDOWS32
        0x01,              # VFT_APP
        0x00,              # subtype
        0x00, 0x00,        # file date
    )


def string_entry(key, value):
    """One String node. wValueLength is a WORD count for text nodes."""
    val = _sz(value)
    return _node(key, value=val, w_type=1, value_length=len(val) // 2)


def string_table(lang_codepage="040904B0", strings=None):
    strings = strings if strings is not None else {}
    body = b"".join(_pad4(string_entry(k, v)) for k, v in strings.items())
    return _node(lang_codepage, children=body, w_type=1)


def string_file_info(tables):
    body = b"".join(_pad4(t) for t in tables)
    return _node("StringFileInfo", children=body, w_type=1)


def var_file_info(translations=((0x0409, 0x04B0),), value_length=None):
    val = b"".join(struct.pack("<HH", l, c) for l, c in translations)
    var = _node("Translation", value=val, w_type=0, value_length=value_length)
    return _node("VarFileInfo", children=_pad4(var), w_type=1)


def version_info(key="VS_VERSION_INFO",
                 ffi=None,
                 children=b"",
                 value_length=None,
                 length_override=None):
    """Top-level VS_VERSIONINFO envelope."""
    ffi = fixed_file_info() if ffi is None else ffi
    return _node(key, value=ffi, children=children, w_type=0,
                 value_length=value_length,
                 length_override=length_override)


# =====================================================================
# Baseline
# =====================================================================

_BASELINE_STRINGS = {
    "CompanyName": "MalX Labs",
    "FileDescription": "IOCX test fixture",
    "FileVersion": "10.0.0.1",
    "InternalName": "fixture",
    "LegalCopyright": "\u00a9 MalX Labs",
    "OriginalFilename": "FIXTURE.EXE",
    "ProductName": "IOCX",
    "ProductVersion": "10.0.0.1",
}


def baseline():
    """A well-formed blob: valid envelope, FFI, one string table, one Var."""
    children = _pad4(string_file_info([string_table(strings=_BASELINE_STRINGS)]))
    children += _pad4(var_file_info())
    return version_info(children=children)


# =====================================================================
# Malformed variants - one named fault each
# =====================================================================

def szkey_mismatch():
    """szKey != VS_VERSION_INFO -> header_ok False."""
    children = _pad4(string_file_info([string_table(strings=_BASELINE_STRINGS)]))
    return version_info(key="VS_VERSION_BAD", children=children)


def length_inconsistent():
    """wLength larger than the buffer -> length_consistent False."""
    return version_info(length_override=0xFFFF)


def truncated_header():
    """Fewer than 6 bytes -> too_short."""
    return b"\x40\x01\x34"


def ffi_bad_signature():
    return version_info(ffi=fixed_file_info(signature=0xDEADBEEF))


def ffi_bad_struct_version():
    return version_info(ffi=fixed_file_info(struct_version=0x00020000))


def ffi_truncated():
    """wValueLength non-zero but under 52 -> fixed_file_info_truncated."""
    return version_info(ffi=b"\x00" * 16, value_length=16)


def ffi_absent():
    """wValueLength == 0 is a legitimate omission, not a defect."""
    children = _pad4(string_file_info([string_table(strings=_BASELINE_STRINGS)]))
    return version_info(ffi=b"", children=children)


def unknown_child():
    """A child that is neither StringFileInfo nor VarFileInfo."""
    bogus = _node("NotAKnownChild", children=_pad4(_node("x")), w_type=1)
    return version_info(children=_pad4(bogus))


def child_length_invalid():
    """A child claiming more bytes than the envelope holds."""
    sfi = string_file_info([string_table(strings=_BASELINE_STRINGS)])
    bad = _u16(0xFFFE) + sfi[2:]
    return version_info(children=_pad4(bad))


def child_max_exceeded(count=300):
    """More children than the 256 hard cap."""
    one = _pad4(_node("NotAKnownChild", children=_pad4(_node("x")), w_type=1))
    return version_info(children=one * count)


def lang_codepage_key():
    """StringTable key that is not 8 hex characters."""
    tbl = string_table(lang_codepage="ENGLISHX", strings=_BASELINE_STRINGS)
    return version_info(children=_pad4(string_file_info([tbl])))


def string_length_invalid():
    """A String node whose wLength overruns its table."""
    entry = string_entry("CompanyName", "MalX Labs")
    bad = _u16(0xFFFE) + entry[2:]
    tbl = _node("040904B0", children=_pad4(bad), w_type=1)
    return version_info(children=_pad4(string_file_info([tbl])))


def translation_not_dword_aligned():
    """Translation wValueLength not a DWORD multiple."""
    return version_info(children=_pad4(var_file_info(value_length=6)))


def bidi_in_company_name():
    """
    Not a structural defect - the parser accepts it. Exercises the
    projection's control/bidi stripping, which is where it matters.
    """
    strings = dict(_BASELINE_STRINGS)
    strings["CompanyName"] = "MalX \u202eLabs\u202c\nInc"
    return version_info(children=_pad4(string_file_info([string_table(strings=strings)])))


def deeply_nested_tables(count=200):
    """Many string tables - exercises the projection's table cap."""
    tables = [string_table(lang_codepage=f"{i:04X}04B0",
                           strings={"CompanyName": f"T{i}"})
              for i in range(count)]
    return version_info(children=_pad4(string_file_info(tables)))


CASES = {
    "baseline": baseline,
    "szkey_mismatch": szkey_mismatch,
    "length_inconsistent": length_inconsistent,
    "truncated_header": truncated_header,
    "ffi_bad_signature": ffi_bad_signature,
    "ffi_bad_struct_version": ffi_bad_struct_version,
    "ffi_truncated": ffi_truncated,
    "ffi_absent": ffi_absent,
    "unknown_child": unknown_child,
    "child_length_invalid": child_length_invalid,
    "child_max_exceeded": child_max_exceeded,
    "lang_codepage_key": lang_codepage_key,
    "string_length_invalid": string_length_invalid,
    "translation_not_dword_aligned": translation_not_dword_aligned,
    "bidi_in_company_name": bidi_in_company_name,
    "deeply_nested_tables": deeply_nested_tables,
}
