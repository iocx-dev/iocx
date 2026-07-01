# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.parser_version_info.

Strategy:
- Decoder tests build VS_VERSIONINFO byte buffers directly via helpers.
  This isolates the decoder from pefile and gives precise control over
  every malformation we want to exercise.
- Locator tests use a minimal duck-typed fake-pe object so we can construct
  resource trees with arbitrary RT_VERSION leaf populations without needing
  real PE binaries on disk.
- Determinism tests assert byte-for-byte stable output across repeated runs
  on the same input, which is the headline property of the module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pytest

from iocx.parsers.pe_version_info import (
    build_version_info,
    _align4,
    _decode_string_file_info,
    _decode_var_file_info,
    _decode_vs_versioninfo,
    _find_first_version_leaf,
    _read_utf16_sz,
    _u16,
    _VS_FFI_SIGNATURE,
    _VS_FFI_STRUCT_VERSION,
    _VS_VERSION_INFO_KEY,
    RT_VERSION,
)


# =================================================================
# Byte-level builders for VS_VERSIONINFO test fixtures
# =================================================================

def _utf16_sz(s: str) -> bytes:
    """Encode a string as NUL-terminated UTF-16LE."""
    return s.encode("utf-16-le") + b"\x00\x00"


def _pad4(buf: bytes) -> bytes:
    """Pad a buffer to a 4-byte boundary."""
    pad = (-len(buf)) & 3
    return buf + b"\x00" * pad


def _build_ffi(
    signature: int = _VS_FFI_SIGNATURE,
    struct_version: int = _VS_FFI_STRUCT_VERSION,
    file_version_ms: int = 0x00010000,
    file_version_ls: int = 0x00020003,
    product_version_ms: int = 0x00010000,
    product_version_ls: int = 0x00020003,
    file_flags_mask: int = 0,
    file_flags: int = 0,
    file_os: int = 0x00040004,
    file_type: int = 1,
    file_subtype: int = 0,
    file_date_ms: int = 0,
    file_date_ls: int = 0,
) -> bytes:
    """Build a 52-byte VS_FIXEDFILEINFO blob."""
    return struct.pack(
        "<13I",
        signature, struct_version,
        file_version_ms, file_version_ls,
        product_version_ms, product_version_ls,
        file_flags_mask, file_flags,
        file_os, file_type, file_subtype,
        file_date_ms, file_date_ls,
    )


def _build_string(key: str, value: str) -> bytes:
    """
    Build a single String entry:
        wLength, wValueLength (chars including NUL), wType=1, szKey, [pad], Value
    """
    key_bytes = _utf16_sz(key)
    value_bytes = _utf16_sz(value)
    value_chars = len(value_bytes) // 2  # wValueLength is in WORDs for text
    header_and_key = struct.pack("<HHH", 0, value_chars, 1) + key_bytes
    header_and_key_padded = _pad4(header_and_key)
    full = header_and_key_padded + value_bytes
    full = _pad4(full)
    # Patch wLength in place
    return struct.pack("<H", len(full)) + full[2:]


def _build_string_table(lang_codepage: str, strings: Dict[str, str]) -> bytes:
    """Build a StringTable containing the given String entries."""
    key_bytes = _utf16_sz(lang_codepage)
    header_and_key = struct.pack("<HHH", 0, 0, 1) + key_bytes
    header_and_key = _pad4(header_and_key)
    body = b"".join(_build_string(k, v) for k, v in strings.items())
    full = header_and_key + body
    full = _pad4(full)
    return struct.pack("<H", len(full)) + full[2:]


def _build_string_file_info(tables: List[Tuple[str, Dict[str, str]]]) -> bytes:
    """Build a StringFileInfo child containing the given StringTables."""
    key_bytes = _utf16_sz("StringFileInfo")
    header_and_key = struct.pack("<HHH", 0, 0, 1) + key_bytes
    header_and_key = _pad4(header_and_key)
    body = b"".join(_build_string_table(lc, s) for lc, s in tables)
    full = header_and_key + body
    full = _pad4(full)
    return struct.pack("<H", len(full)) + full[2:]


def _build_var(key: str, translations: List[Tuple[int, int]]) -> bytes:
    """Build a single Var entry containing the given (lang, codepage) pairs."""
    key_bytes = _utf16_sz(key)
    payload = b"".join(struct.pack("<HH", lang, cp) for lang, cp in translations)
    header_and_key = struct.pack("<HHH", 0, len(payload), 0) + key_bytes
    header_and_key = _pad4(header_and_key)
    full = header_and_key + payload
    full = _pad4(full)
    return struct.pack("<H", len(full)) + full[2:]


def build_var_file_info(vars: List[Tuple[str, List[Tuple[int, int]]]]) -> bytes:
    """Build a VarFileInfo child containing the given Vars."""
    key_bytes = _utf16_sz("VarFileInfo")
    header_and_key = struct.pack("<HHH", 0, 0, 1) + key_bytes
    header_and_key = _pad4(header_and_key)
    body = b"".join(build_var(k, t) for k, t in vars)
    full = header_and_key + body
    full = _pad4(full)
    return struct.pack("<H", len(full)) + full[2:]


def _build_vs_versioninfo(
    *,
    sz_key: str = _VS_VERSION_INFO_KEY,
    ffi: Optional[bytes] = None,
    string_file_info: Optional[bytes] = None,
    var_file_info: Optional[bytes] = None,
    w_length_override: Optional[int] = None,
    w_value_length_override: Optional[int] = None,
    w_type: int = 0,
) -> bytes:
    """Build a complete VS_VERSIONINFO blob with optional FFI and children."""
    if ffi is None:
        ffi = b""
    sz_key_bytes = _utf16_sz(sz_key)
    value_length = w_value_length_override if w_value_length_override is not None else len(ffi)
    header_and_key = struct.pack("<HHH", 0, value_length, w_type) + sz_key_bytes
    header_and_key = _pad4(header_and_key)
    body = ffi
    if string_file_info:
        body = _pad4(body) + string_file_info
    if var_file_info:
        body = _pad4(body) + var_file_info
    full = header_and_key + body
    full = _pad4(full)
    w_length = w_length_override if w_length_override is not None else len(full)
    return struct.pack("<H", w_length) + full[2:]


def _build_var_file_info(vars_: List[Tuple[str, List[Tuple[int, int]]]]) -> bytes:
    """
    Build a VarFileInfo child containing the given Vars.

    Each entry in vars_ is (var_key, [(lang, codepage), ...]).
    """
    key_bytes = _utf16_sz("VarFileInfo")
    header_and_key = struct.pack("<HHH", 0, 0, 1) + key_bytes
    header_and_key = _pad4(header_and_key)
    body = b"".join(_build_var(k, t) for k, t in vars_)
    full = header_and_key + body
    full = _pad4(full)
    return struct.pack("<H", len(full)) + full[2:]


# =================================================================
# Fake pefile objects for locator tests
# =================================================================
@dataclass
class _FakeDataStruct:
    OffsetToData: int
    Size: int


@dataclass
class _FakeDataEntry:
    struct: _FakeDataStruct

    @classmethod
    def make(cls, offset_to_data: int, size: int) -> "_FakeDataEntry":
        return cls(struct=_FakeDataStruct(offset_to_data, size))


@dataclass
class _FakeLeafEntry:
    """A language-level entry that wraps a data leaf."""
    id: Optional[int]
    data: _FakeDataEntry

    def __init__(self, lang_id: Optional[int], offset_to_data: int, size: int):
        self.id = lang_id
        self.data = _FakeDataEntry.make(offset_to_data, size)


@dataclass
class _FakeDirectory:
    entries: list = field(default_factory=list)

    def __init__(self, entries):
        self.entries = entries


@dataclass
class _FakeNameEntry:
    """A name-level entry whose .directory holds language entries."""
    id: Optional[int]
    directory: _FakeDirectory

    def __init__(self, name_id: Optional[int], lang_entries):
        self.id = name_id
        self.directory = _FakeDirectory(lang_entries)


@dataclass
class _FakeTypeEntry:
    """A type-level entry whose .directory holds name entries."""
    id: int
    directory: _FakeDirectory

    def __init__(self, type_id: int, name_entries):
        self.id = type_id
        self.directory = _FakeDirectory(name_entries)


class _FakePE:
    """Minimal duck-typed pe object that exposes only what the parser uses."""
    def __init__(self, root_entries, raw_data_by_rva: Dict[int, bytes],
                 raise_on_get_data: bool = False):
        self.DIRECTORY_ENTRY_RESOURCE = _FakeDirectory(root_entries)
        self._raw = raw_data_by_rva
        self._raise = raise_on_get_data

    def get_data(self, rva: int, size: int) -> bytes:
        if self._raise:
            raise RuntimeError("simulated read failure")
        if rva not in self._raw:
            raise ValueError(f"no fixture data at rva {rva}")
        return self._raw[rva][:size]


# =================================================================
# Low-level helper tests
# =================================================================

class TestAlign4:
    @pytest.mark.parametrize("n,expected", [
        (0, 0), (1, 4), (2, 4), (3, 4), (4, 4),
        (5, 8), (7, 8), (8, 8), (9, 12),
        (100, 100), (101, 104),
    ])
    def test_aligns_up_to_multiple_of_4(self, n, expected):
        assert _align4(n) == expected


class TestU16:
    def test_little_endian_decode(self):
        assert _u16(b"\x01\x00", 0) == 1
        assert _u16(b"\x00\x01", 0) == 256
        assert _u16(b"\xFF\xFF", 0) == 0xFFFF

    def test_offset_into_buffer(self):
        buf = b"\xAA\xBB\xCC\xDD"
        assert _u16(buf, 0) == 0xBBAA
        assert _u16(buf, 2) == 0xDDCC

    def test_raises_struct_error_on_overrun(self):
        with pytest.raises(struct.error):
            _u16(b"\x01", 0)


class TestReadUtf16Sz:
    def test_reads_simple_ascii_string(self):
        buf = _utf16_sz("Hello")
        s, consumed = _read_utf16_sz(buf, 0)
        assert s == "Hello"
        assert consumed == len(buf)

    def test_reads_empty_string(self):
        buf = b"\x00\x00"
        s, consumed = _read_utf16_sz(buf, 0)
        assert s == ""
        assert consumed == 2

    def test_reads_at_offset(self):
        prefix = b"\xFF\xFF\xFF\xFF"
        buf = prefix + _utf16_sz("World")
        s, consumed = _read_utf16_sz(buf, len(prefix))
        assert s == "World"
        assert consumed == len(buf) - len(prefix)

    def test_reads_unicode(self):
        buf = _utf16_sz("café")
        s, consumed = _read_utf16_sz(buf, 0)
        assert s == "café"
        assert consumed == len(buf)

    def test_handles_unterminated_string_at_eob(self):
        # No NUL terminator — should consume to end of buffer
        buf = "VS_VERSION_INFO".encode("utf-16-le")
        s, consumed = _read_utf16_sz(buf, 0)
        # The function increments by 2 for the assumed NUL even if absent
        assert s == "VS_VERSION_INFO"
        assert consumed == len(buf) + 2

    def test_handles_malformed_utf16_with_replacement(self):
        # Odd-byte sequence that decodes with replacement chars
        buf = b"\x41\x00\xFF\xD8\x00\x00"  # 'A' + lone high surrogate + NUL
        s, consumed = _read_utf16_sz(buf, 0)
        assert "A" in s
        assert "\uFFFD" in s
        assert consumed == 6


# =================================================================
# Decoder tests — top-level header
# =================================================================

class TestDecodeHeader:
    def test_empty_buffer_too_short(self):
        out = _decode_vs_versioninfo(b"")
        assert out["decoded"] is False
        assert "too_short" in out["errors"]

    def test_5_byte_buffer_too_short(self):
        out = _decode_vs_versioninfo(b"\x00" * 5)
        assert out["decoded"] is False
        assert "too_short" in out["errors"]

    def test_minimal_valid_header_decodes(self):
        buf = _build_vs_versioninfo()
        out = _decode_vs_versioninfo(buf)
        assert out["decoded"] is True
        assert out["header_ok"] is True
        assert out["length_consistent"] is True

    def test_szkey_mismatch_flags_header_not_ok(self):
        buf = _build_vs_versioninfo(sz_key="VS_VERSION_BAD")
        out = _decode_vs_versioninfo(buf)
        assert out["decoded"] is True
        assert out["header_ok"] is False
        assert out["length_consistent"] is True

    def test_wlength_too_large_flags_inconsistent(self):
        buf = _build_vs_versioninfo(w_length_override=0xFFFF)
        out = _decode_vs_versioninfo(buf)
        assert out["length_consistent"] is False

    def test_wlength_too_small_flags_inconsistent(self):
        buf = _build_vs_versioninfo(w_length_override=4)
        out = _decode_vs_versioninfo(buf)
        assert out["length_consistent"] is False

    def test_w_type_recorded(self):
        buf = _build_vs_versioninfo(w_type=0)
        out = _decode_vs_versioninfo(buf)
        assert out["w_type"] == 0

        buf = _build_vs_versioninfo(w_type=1)
        out = _decode_vs_versioninfo(buf)
        assert out["w_type"] == 1


# =================================================================
# Decoder tests — VS_FIXEDFILEINFO
# =================================================================

class TestDecodeFixedFileInfo:
    def test_valid_ffi_decoded(self):
        ffi = _build_ffi()
        buf = _build_vs_versioninfo(ffi=ffi)
        out = _decode_vs_versioninfo(buf)

        assert out["fixed_file_info"] is not None
        ffi_out = out["fixed_file_info"]
        assert ffi_out["signature"] == _VS_FFI_SIGNATURE
        assert ffi_out["signature_ok"] is True
        assert ffi_out["struct_version"] == _VS_FFI_STRUCT_VERSION
        assert ffi_out["struct_version_ok"] is True
        assert ffi_out["file_version"] == (0x00010000, 0x00020003)
        assert ffi_out["product_version"] == (0x00010000, 0x00020003)

    def test_bad_signature_flagged(self):
        ffi = _build_ffi(signature=0xDEADBEEF)
        buf = _build_vs_versioninfo(ffi=ffi)
        out = _decode_vs_versioninfo(buf)
        assert out["fixed_file_info"]["signature"] == 0xDEADBEEF
        assert out["fixed_file_info"]["signature_ok"] is False
        assert out["fixed_file_info"]["struct_version_ok"] is True

    def test_bad_struct_version_flagged(self):
        ffi = _build_ffi(struct_version=0x00020000)
        buf = _build_vs_versioninfo(ffi=ffi)
        out = _decode_vs_versioninfo(buf)
        assert out["fixed_file_info"]["struct_version_ok"] is False
        assert out["fixed_file_info"]["signature_ok"] is True

    def test_absent_ffi_returns_none(self):
        buf = _build_vs_versioninfo(ffi=b"", w_value_length_override=0)
        out = _decode_vs_versioninfo(buf)
        assert out["fixed_file_info"] is None
        assert "fixed_file_info_truncated" not in out["errors"]

    def test_truncated_ffi_flagged(self):
        # wValueLength claims 30 (< 52) but non-zero
        buf = _build_vs_versioninfo(
            ffi=b"\x00" * 30,
            w_value_length_override=30,
        )
        out = _decode_vs_versioninfo(buf)
        assert "fixed_file_info_truncated" in out["errors"]
        assert out["fixed_file_info"] is None

    def test_ffi_extending_past_buffer_flagged(self):
        # wValueLength claims 100 but buffer only has space for ~52
        ffi = _build_ffi()
        buf = _build_vs_versioninfo(ffi=ffi, w_value_length_override=0xFF00)
        out = _decode_vs_versioninfo(buf)
        # Either truncated or unpack error — but FFI should not be decoded
        assert out["fixed_file_info"] is None

    def test_all_ffi_fields_decoded(self):
        ffi = _build_ffi(
            file_flags_mask=0xFF,
            file_flags=0x0F,
            file_os=0x00040004,
            file_type=2,
            file_subtype=5,
            file_date_ms=0xCAFEBABE,
            file_date_ls=0xDEADBEEF,
        )
        buf = _build_vs_versioninfo(ffi=ffi)
        out = _decode_vs_versioninfo(buf)
        ffi_out = out["fixed_file_info"]
        assert ffi_out["file_flags_mask"] == 0xFF
        assert ffi_out["file_flags"] == 0x0F
        assert ffi_out["file_os"] == 0x00040004
        assert ffi_out["file_type"] == 2
        assert ffi_out["file_subtype"] == 5
        assert ffi_out["file_date"] == (0xCAFEBABE, 0xDEADBEEF)


# =================================================================
# Decoder tests — StringFileInfo
# =================================================================

class TestDecodeStringFileInfo:
    def test_single_string_table_decoded(self):
        sfi = _build_string_file_info([
            ("040904B0", {"CompanyName": "MalX Labs", "ProductName": "iocx"}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)

        assert len(out["string_file_info"]) == 1
        sfi_out = out["string_file_info"][0]
        assert len(sfi_out["tables"]) == 1
        table = sfi_out["tables"][0]
        assert table["lang_codepage"] == "040904B0"
        assert table["errors"] == []
        assert table["strings"]["CompanyName"] == "MalX Labs"
        assert table["strings"]["ProductName"] == "iocx"

    def test_bad_lang_codepage_key_flagged(self):
        sfi = _build_string_file_info([
            ("ENGLISHX", {"CompanyName": "MalX Labs"}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)

        table = out["string_file_info"][0]["tables"][0]
        assert "lang_codepage_key" in table["errors"]
        # But strings should still decode
        assert table["strings"]["CompanyName"] == "MalX Labs"

    def test_lang_codepage_wrong_length_flagged(self):
        sfi = _build_string_file_info([
            ("0409", {"CompanyName": "X"}),  # only 4 hex chars
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        table = out["string_file_info"][0]["tables"][0]
        assert "lang_codepage_key" in table["errors"]

    def test_lang_codepage_lowercase_hex_accepted(self):
        sfi = _build_string_file_info([
            ("040904b0", {"CompanyName": "X"}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        table = out["string_file_info"][0]["tables"][0]
        assert "lang_codepage_key" not in table["errors"]

    def test_multiple_string_tables_decoded(self):
        sfi = _build_string_file_info([
            ("040904B0", {"CompanyName": "A"}),
            ("080904B0", {"CompanyName": "B"}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        tables = out["string_file_info"][0]["tables"]
        assert len(tables) == 2
        assert tables[0]["strings"]["CompanyName"] == "A"
        assert tables[1]["strings"]["CompanyName"] == "B"

    def test_string_values_bounded_at_512_chars(self):
        long_value = "X" * 1000
        sfi = _build_string_file_info([
            ("040904B0", {"Long": long_value}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        table = out["string_file_info"][0]["tables"][0]
        assert len(table["strings"]["Long"]) == 512

    def test_string_keys_bounded_at_128_chars(self):
        long_key = "K" * 200
        sfi = _build_string_file_info([
            ("040904B0", {long_key: "value"}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        table = out["string_file_info"][0]["tables"][0]
        stored_key = next(iter(table["strings"].keys()))
        assert len(stored_key) == 128

    def test_empty_string_value(self):
        sfi = _build_string_file_info([
            ("040904B0", {"EmptyValue": ""}),
        ])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)
        out = _decode_vs_versioninfo(buf)
        table = out["string_file_info"][0]["tables"][0]
        assert table["strings"]["EmptyValue"] == ""


# =================================================================
# Decoder tests — VarFileInfo
# =================================================================

class TestDecodeVarFileInfo:
    def test_single_translation_decoded(self):
        vfi = _build_var_file_info([("Translation", [(0x0409, 0x04B0)])])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), var_file_info=vfi)
        out = _decode_vs_versioninfo(buf)

        assert len(out["var_file_info"]) == 1
        vfi_out = out["var_file_info"][0]
        assert vfi_out["errors"] == []
        assert len(vfi_out["vars"]) == 1
        var = vfi_out["vars"][0]
        assert var["key"] == "Translation"
        assert var["translations"] == [{"lang": 0x0409, "codepage": 0x04B0}]

    def test_multiple_translations_decoded(self):
        translations = [(0x0409, 0x04B0), (0x0809, 0x04B0), (0x0407, 0x04E4)]
        vfi = _build_var_file_info([("Translation", translations)])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), var_file_info=vfi)
        out = _decode_vs_versioninfo(buf)

        var = out["var_file_info"][0]["vars"][0]
        assert len(var["translations"]) == 3
        assert var["translations"][0] == {"lang": 0x0409, "codepage": 0x04B0}
        assert var["translations"][2] == {"lang": 0x0407, "codepage": 0x04E4}

    def test_misaligned_translation_flagged(self):
        # Build a Var manually with wValueLength=6 (not DWORD-aligned)
        key_bytes = _utf16_sz("Translation")
        payload = b"\x09\x04\xB0\x04\xCC\xCC"  # 6 bytes
        header_and_key = struct.pack("<HHH", 0, 6, 0) + key_bytes
        header_and_key = _pad4(header_and_key)
        var = header_and_key + payload
        var = _pad4(var)
        var = struct.pack("<H", len(var)) + var[2:]

        # Wrap in VarFileInfo
        vfi_key = _utf16_sz("VarFileInfo")
        vfi_header = struct.pack("<HHH", 0, 0, 1) + vfi_key
        vfi_header = _pad4(vfi_header)
        vfi = vfi_header + var
        vfi = _pad4(vfi)
        vfi = struct.pack("<H", len(vfi)) + vfi[2:]

        buf = _build_vs_versioninfo(ffi=_build_ffi(), var_file_info=vfi)
        out = _decode_vs_versioninfo(buf)

        vfi_out = out["var_file_info"][0]
        assert "translation_not_dword_aligned" in vfi_out["errors"]

    def test_empty_var_file_info(self):
        vfi = _build_var_file_info([])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), var_file_info=vfi)
        out = _decode_vs_versioninfo(buf)
        assert out["var_file_info"][0]["vars"] == []
        assert out["var_file_info"][0]["errors"] == []


# =================================================================
# Decoder tests — child dispatch and unknown children
# =================================================================

class TestChildDispatch:
    def test_unknown_child_flagged(self):
        # Build a child with an unrecognised key
        key_bytes = _utf16_sz("UnknownChild")
        header = struct.pack("<HHH", 0, 0, 1) + key_bytes
        header = _pad4(header)
        child = struct.pack("<H", len(header)) + header[2:]

        sz_key = _utf16_sz(_VS_VERSION_INFO_KEY)
        ffi = _build_ffi()
        env_header = struct.pack("<HHH", 0, len(ffi), 0) + sz_key
        env_header = _pad4(env_header)
        body = ffi + child
        full = env_header + body
        full = _pad4(full)
        buf = struct.pack("<H", len(full)) + full[2:]

        out = _decode_vs_versioninfo(buf)
        assert "unknown_child" in out["errors"]

    def test_child_with_invalid_length_flagged(self):
        # Build a "StringFileInfo" child whose wLength claims to extend past the buffer
        sz_key = _utf16_sz(_VS_VERSION_INFO_KEY)
        env_header = struct.pack("<HHH", 0, 0, 0) + sz_key
        env_header = _pad4(env_header)

        bad_child_header = struct.pack("<HHH", 0xFF00, 0, 1) + _utf16_sz("StringFileInfo")
        body = env_header + _pad4(bad_child_header)
        full = body
        buf = struct.pack("<H", len(full)) + full[2:]

        out = _decode_vs_versioninfo(buf)
        assert "child_length_invalid" in out["errors"]

    def test_both_sfi_and_vfi_decoded(self):
        sfi = _build_string_file_info([("040904B0", {"X": "Y"})])
        vfi = _build_var_file_info([("Translation", [(0x0409, 0x04B0)])])
        buf = _build_vs_versioninfo(
            ffi=_build_ffi(),
            string_file_info=sfi,
            var_file_info=vfi,
        )
        out = _decode_vs_versioninfo(buf)
        assert len(out["string_file_info"]) == 1
        assert len(out["var_file_info"]) == 1


# =================================================================
# Decoder helper tests — direct calls
# =================================================================

class TestDecodeStringFileInfoDirect:
    def test_truncated_string_table_header(self):
        # Less than 6 bytes available — loop should not enter, no errors
        result = _decode_string_file_info(b"\x00\x00", 0, 2)
        assert result == {"tables": [], "errors": []}

    def test_string_table_length_extends_past_end(self):
        # t_len = 100 but end = 10
        buf = struct.pack("<H", 100) + b"\x00" * 8
        result = _decode_string_file_info(buf, 0, 10)
        assert "string_table_length" in result["errors"]


class TestDecodeVarFileInfoDirect:
    def test_truncated_var_header(self):
        result = _decode_var_file_info(b"\x00\x00", 0, 2)
        assert result == {"vars": [], "errors": []}

    def test_var_length_extends_past_end(self):
        buf = struct.pack("<H", 100) + b"\x00" * 8
        result = _decode_var_file_info(buf, 0, 10)
        assert "var_length" in result["errors"]


# =================================================================
# Locator tests
# =================================================================

class TestLocator:
    def test_returns_none_when_no_resource_directory(self):
        # _find_first_version_leaf only consumes root_dir.entries
        empty_dir = _FakeDirectory([])
        assert _find_first_version_leaf(empty_dir) is None

    def test_returns_none_when_no_rt_version(self):
        # Has resources but no RT_VERSION
        root = _FakeDirectory([
            _FakeTypeEntry(type_id=6, name_entries=[]),  # RT_STRING
        ])
        assert _find_first_version_leaf(root) is None

    def test_finds_single_rt_version_leaf(self):
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=100)
        root = _FakeDirectory([
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ])
        result = _find_first_version_leaf(root)
        assert result is leaf

    def test_deterministic_ordering_by_name_then_language(self):
        # Multiple leaves with mixed name and language ids
        leaf_a = _FakeLeafEntry(lang_id=0x0809, offset_to_data=0x1000, size=10)
        leaf_b = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x2000, size=10)
        leaf_c = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x3000, size=10)
        root = _FakeDirectory([
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[
                    _FakeNameEntry(name_id=2, lang_entries=[leaf_a]),
                    _FakeNameEntry(name_id=1, lang_entries=[leaf_b, leaf_c]),
                ],
            ),
        ])
        # name_id=1 comes before name_id=2; within name_id=1, language 0x0409
        # appears first; so leaf_b should be returned.
        result = _find_first_version_leaf(root)
        assert result is leaf_b

    def test_non_integer_keys_pushed_to_end(self):
        leaf_named = _FakeLeafEntry(lang_id=None, offset_to_data=0x1000, size=10)
        leaf_id = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x2000, size=10)
        root = _FakeDirectory([
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[
                    _FakeNameEntry(name_id=1, lang_entries=[leaf_named, leaf_id]),
                ],
            ),
        ])
        # leaf_id (lang=0x0409) should beat leaf_named (lang=None)
        result = _find_first_version_leaf(root)
        assert result is leaf_id

    def test_skips_type_entries_without_directory(self):
        # A type entry with id=RT_VERSION but no .directory attribute
        broken = type("Broken", (), {"id": RT_VERSION})()
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=10)
        root = _FakeDirectory([
            broken,
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ])
        assert _find_first_version_leaf(root) is leaf

    def test_returns_none_on_attribute_error_during_walk(self):
        # Root with .entries that raises on iteration
        class Broken:
            @property
            def entries(self):
                raise AttributeError("simulated")
        assert _find_first_version_leaf(Broken()) is None

    def test_locator_skips_name_entry_without_directory(self):
        """
        Cover line 92: a Name-level entry that lacks a .directory attribute
        is skipped, and the walk continues with the next name entry.
        """
        # First name entry has no directory — should be skipped (hits line 92)
        name_no_directory = type("NameNoDir", (), {"id": 1})()

        # Second name entry is well-formed — proves the walk continues past
        # the skip, not bails out
        valid_leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=10)
        valid_name = _FakeNameEntry(name_id=2, lang_entries=[valid_leaf])

        # Type entry's directory contains both
        type_dir = _FakeDirectory([name_no_directory, valid_name])
        type_entry = type("TypeEntry", (), {
            "id": RT_VERSION,
            "directory": type_dir,
        })()

        root = _FakeDirectory([type_entry])
        result = _find_first_version_leaf(root)

        # The walk should have skipped the broken name entry and found the valid leaf
        assert result is valid_leaf

    def test_locator_skips_lang_entry_without_data(self):
        """
        Cover the analogous lang-layer skip: a Language-level entry that lacks
        a .data attribute is skipped.
        """
        lang_no_data = type("LangNoData", (), {"id": 0x0409})()
        valid_leaf = _FakeLeafEntry(lang_id=0x0809, offset_to_data=0x1000, size=10)

        name_entry = _FakeNameEntry(name_id=1, lang_entries=[lang_no_data, valid_leaf])
        type_dir = _FakeDirectory([name_entry])
        type_entry = type("TypeEntry", (), {
            "id": RT_VERSION,
            "directory": type_dir,
        })()

        root = _FakeDirectory([type_entry])
        result = _find_first_version_leaf(root)
        assert result is valid_leaf


# =================================================================
# build_version_info entry point tests
# =================================================================

class TestBuildVersionInfo:
    def test_returns_none_when_no_resource_directory_attr(self):
        # PE object lacking DIRECTORY_ENTRY_RESOURCE entirely
        pe = type("FakePE", (), {})()
        assert build_version_info(pe) is None

    def test_returns_none_when_no_rt_version_leaf(self):
        pe = _FakePE(root_entries=[], raw_data_by_rva={})
        assert build_version_info(pe) is None

    def test_full_roundtrip_with_valid_blob(self):
        ffi = _build_ffi()
        sfi = _build_string_file_info([("040904B0", {"CompanyName": "MalX Labs"})])
        vfi = _build_var_file_info([("Translation", [(0x0409, 0x04B0)])])
        blob = _build_vs_versioninfo(ffi=ffi, string_file_info=sfi, var_file_info=vfi)

        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=len(blob))
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={0x1000: blob})

        out = build_version_info(pe)
        assert out is not None
        assert out["rva"] == 0x1000
        assert out["size"] == len(blob)
        assert out["decoded"] is True
        assert out["header_ok"] is True
        assert out["fixed_file_info"]["signature_ok"] is True
        assert out["string_file_info"][0]["tables"][0]["strings"]["CompanyName"] == "MalX Labs"
        assert out["var_file_info"][0]["vars"][0]["translations"][0]["lang"] == 0x0409

    def test_returns_tombstone_dict_when_get_data_raises(self):
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=100)
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={}, raise_on_get_data=True)

        out = build_version_info(pe)
        assert out is not None
        assert out["decoded"] is False
        assert "read_failed" in out["errors"]
        assert out["rva"] == 0x1000
        assert out["size"] == 100

    def test_returns_tombstone_when_leaf_struct_unpack_fails(self):
        # Leaf with no .data attribute
        broken_leaf = type("BrokenLeaf", (), {"id": 0x0409})()
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[broken_leaf])],
            ),
        ]
        # The locator filters out leaves without .data, so this should return None
        pe = _FakePE(root_entries, raw_data_by_rva={})
        assert build_version_info(pe) is None

    def test_deterministic_leaf_selection_with_multiple_leaves(self):
        blob_a = _build_vs_versioninfo(
            ffi=_build_ffi(),
            string_file_info=_build_string_file_info([
                ("040904B0", {"ProductName": "FromLeafA"}),
            ]),
        )
        blob_b = _build_vs_versioninfo(
            ffi=_build_ffi(),
            string_file_info=_build_string_file_info([
                ("040904B0", {"ProductName": "FromLeafB"}),
            ]),
        )

        leaf_a = _FakeLeafEntry(lang_id=0x0809, offset_to_data=0x2000, size=len(blob_a))
        leaf_b = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=len(blob_b))

        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[
                    _FakeNameEntry(name_id=1, lang_entries=[leaf_a, leaf_b]),
                ],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={0x1000: blob_b, 0x2000: blob_a})

        out = build_version_info(pe)
        # Sort by language id: 0x0409 < 0x0809, so leaf_b should win
        assert out["rva"] == 0x1000
        assert out["string_file_info"][0]["tables"][0]["strings"]["ProductName"] == "FromLeafB"


# =================================================================
# Determinism tests
# =================================================================

class TestDeterminism:
    """
    Headline property: identical input produces identical output across runs.
    These tests don't depend on time, OS, or library version.
    """

    def test_repeated_decode_produces_identical_dicts(self):
        ffi = _build_ffi()
        sfi = _build_string_file_info([("040904B0", {"CompanyName": "MalX Labs"})])
        vfi = _build_var_file_info([("Translation", [(0x0409, 0x04B0)])])
        buf = _build_vs_versioninfo(ffi=ffi, string_file_info=sfi, var_file_info=vfi)

        results = [_decode_vs_versioninfo(buf) for _ in range(20)]
        for r in results[1:]:
            assert r == results[0]

    def test_repeated_decode_on_malformed_blob(self):
        # A blob with multiple anomalies — bad szKey + truncated FFI
        buf = _build_vs_versioninfo(
            sz_key="BAD",
            ffi=b"\x00" * 30,
            w_value_length_override=30,
        )
        results = [_decode_vs_versioninfo(buf) for _ in range(20)]
        for r in results[1:]:
            assert r == results[0]

    def test_locator_ordering_stable_across_runs(self):
        # Build multiple PE objects with the same shape and assert the same
        # leaf is selected every time
        def build_pe():
            leaf_a = _FakeLeafEntry(lang_id=0x0809, offset_to_data=0x2000, size=10)
            leaf_b = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=10)
            return _FakeDirectory([
                _FakeTypeEntry(
                    type_id=RT_VERSION,
                    name_entries=[
                        _FakeNameEntry(name_id=1, lang_entries=[leaf_a, leaf_b]),
                    ],
                ),
            ])

        results = [_find_first_version_leaf(build_pe()) for _ in range(20)]
        offsets = [r.data.struct.OffsetToData for r in results]
        assert all(o == 0x1000 for o in offsets)


# =================================================================
# Output contract tests
# =================================================================

class TestOutputContract:
    """Assert the published output dict shape matches the docstring."""

    REQUIRED_KEYS = {
        "rva", "size", "decoded", "header_ok", "length_consistent",
        "fixed_file_info", "string_file_info", "var_file_info", "errors",
    }

    def test_successful_decode_has_all_required_keys(self):
        ffi = _build_ffi()
        blob = _build_vs_versioninfo(ffi=ffi)
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=len(blob))
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={0x1000: blob})
        out = build_version_info(pe)
        assert self.REQUIRED_KEYS.issubset(out.keys())

    def test_string_file_info_is_list(self):
        blob = _build_vs_versioninfo(ffi=_build_ffi())
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=len(blob))
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={0x1000: blob})
        out = build_version_info(pe)
        assert isinstance(out["string_file_info"], list)
        assert isinstance(out["var_file_info"], list)
        assert isinstance(out["errors"], list)

    def test_errors_is_list_even_on_clean_blob(self):
        blob = _build_vs_versioninfo(ffi=_build_ffi())
        leaf = _FakeLeafEntry(lang_id=0x0409, offset_to_data=0x1000, size=len(blob))
        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={0x1000: blob})
        out = build_version_info(pe)
        assert out["errors"] == []


# =================================================================
# Defensive code path coverage
# =================================================================

class TestDefensiveCodePaths:
    """
    Cover the except clauses and edge branches that are defensive against
    malformed input but not reachable through normal buffer construction.

    Strategy: monkeypatch the low-level unpack helpers to raise struct.error
    at the specific call sites. Each test isolates one defensive branch.
    """

    # ---- Line 51-52: leaf.data.struct attribute access raises ----

    def test_build_version_info_handles_leaf_struct_attribute_error(self):
        """
        Cover: try OffsetToData/Size; except (AttributeError, struct.error)
        """
        class _BrokenStruct:
            @property
            def OffsetToData(self):
                raise AttributeError("simulated")

            Size = 100

        class _BrokenDataEntry:
            struct = _BrokenStruct()

        broken_leaf = type("BrokenLeaf", (), {
            "id": 0x0409,
            "data": _BrokenDataEntry(),
        })()

        root_entries = [
            _FakeTypeEntry(
                type_id=RT_VERSION,
                name_entries=[_FakeNameEntry(name_id=1, lang_entries=[broken_leaf])],
            ),
        ]
        pe = _FakePE(root_entries, raw_data_by_rva={})

        out = build_version_info(pe)
        assert out is not None
        assert out["decoded"] is False
        assert out["rva"] is None
        assert out["size"] is None
        assert "leaf_struct_unpack" in out["errors"]

    # ---- Line 92: _find_first_version_leaf except (AttributeError, IndexError) ----

    def test_locator_handles_inner_attribute_error_during_walk(self):
        """
        Cover: except (AttributeError, IndexError) in _find_first_version_leaf.

        Construct a type entry whose .directory.entries raises during iteration
        partway through, not at .entries access time.
        """
        class _BrokenEntries:
            def __iter__(self):
                raise IndexError("simulated mid-walk failure")

        class _BrokenDirectory:
            entries = _BrokenEntries()

        class _BrokenTypeEntry:
            id = RT_VERSION
            directory = _BrokenDirectory()

        root = _FakeDirectory([_BrokenTypeEntry()])
        result = _find_first_version_leaf(root)
        assert result is None

    # ---- Line 158-160: top-level header unpack struct.error ----

    def test_decode_handles_struct_error_in_header_unpack(self, monkeypatch):
        """
        Cover: except struct.error on the top-level u16 reads of wLength,
        wValueLength, wType in _decode_vs_versioninfo.
        """
        import iocx.parsers.pe_version_info as pvi

        call_count = {"n": 0}
        real_u16 = pvi._u16

        def fake_u16(buf, off):
            call_count["n"] += 1
            if call_count["n"] <= 3:
                raise struct.error("simulated header unpack failure")
            return real_u16(buf, off)

        monkeypatch.setattr(pvi, "_u16", fake_u16)

        buf = _build_vs_versioninfo(ffi=_build_ffi())
        out = pvi._decode_vs_versioninfo(buf)

        assert out["decoded"] is False
        assert "header_unpack" in out["errors"]

    # ---- Line 192-193: FFI unpack struct.error ----

    def test_decode_handles_struct_error_in_ffi_unpack(self, monkeypatch):
        """
        Cover: except struct.error when unpacking the 52-byte VS_FIXEDFILEINFO.
        """
        import iocx.parsers.pe_version_info as pvi

        real_unpack_from = struct.unpack_from

        def fake_unpack_from(fmt, buf, offset=0):
            if fmt == "<13I":
                raise struct.error("simulated FFI unpack failure")
            return real_unpack_from(fmt, buf, offset)

        monkeypatch.setattr(pvi.struct, "unpack_from", fake_unpack_from)

        buf = _build_vs_versioninfo(ffi=_build_ffi())
        out = pvi._decode_vs_versioninfo(buf)

        assert "fixed_file_info_unpack" in out["errors"]
        assert out["fixed_file_info"] is None

    # ---- Line 207-209: child header unpack struct.error ----

    def test_decode_handles_struct_error_in_child_header_unpack(self, monkeypatch):
        """
        Cover: except struct.error in the child-dispatch loop's u16 reads.
        """
        import iocx.parsers.pe_version_info as pvi

        # Build a blob with a child present, then make the 4th+ u16 calls fail
        # (first 3 are top-level header, then FFI doesn't use _u16, then
        # children loop starts).
        sfi = _build_string_file_info([("040904B0", {"K": "V"})])
        buf = _build_vs_versioninfo(ffi=_build_ffi(), string_file_info=sfi)

        call_count = {"n": 0}
        real_u16 = pvi._u16

        def fake_u16(buf_, off):
            call_count["n"] += 1
            # Let top-level header (calls 1-3) and FFI processing succeed;
            # fail when the child dispatch loop reads its first u16.
            if call_count["n"] == 4:
                raise struct.error("simulated child header unpack failure")
            return real_u16(buf_, off)

        monkeypatch.setattr(pvi, "_u16", fake_u16)

        out = pvi._decode_vs_versioninfo(buf)
        assert "child_header_unpack" in out["errors"]

    # ---- Line 241-243: string table header struct.error ----

    def test_decode_string_file_info_handles_struct_error_in_header(self, monkeypatch):
        """
        Cover: except struct.error in _decode_string_file_info string table
        header read.
        """
        import iocx.parsers.pe_version_info as pvi

        # Buffer large enough that pos + 6 <= end passes the entry check,
        # but the _u16 call inside the loop raises.
        buf = b"\x10\x00" + b"\x00" * 100

        real_u16 = pvi._u16

        def fake_u16(buf_, off):
            raise struct.error("simulated string_table_header failure")

        monkeypatch.setattr(pvi, "_u16", fake_u16)

        result = pvi._decode_string_file_info(buf, 0, 50)
        assert "string_table_header" in result["errors"]

    # ---- Line 265-267: String entry header struct.error ----

    def test_decode_string_file_info_handles_struct_error_in_string_header(self, monkeypatch):
        """
        Cover: except struct.error when reading a String entry's wLength inside
        a StringTable.
        """
        import iocx.parsers.pe_version_info as pvi

        # Build a complete StringFileInfo containing one StringTable with one String.
        # Using the full SFI builder ensures the body length is sufficient for the
        # inner String loop to execute.
        sfi = _build_string_file_info([("040904B0", {"K": "V"})])

        # Strip the SFI envelope so we hand the StringTable bytes directly to
        # _decode_string_file_info — that function expects to walk StringTables.
        # SFI envelope: 6 bytes header + UTF-16LE "StringFileInfo\0" (30 bytes)
        # + padding to 4-byte boundary.
        sfi_header_len = 6 + len(_utf16_sz("StringFileInfo"))
        sfi_header_len = (sfi_header_len + 3) & ~3
        inner = sfi[sfi_header_len:]

        call_count = {"n": 0}
        real_u16 = pvi._u16

        def fake_u16(buf_, off):
            call_count["n"] += 1
            # Call 1: t_len (string table header) — must succeed so we enter
            #         the inner String loop.
            # Call 2: s_len (String entry header) — fail here to hit "string_header".
            if call_count["n"] >= 2:
                raise struct.error("simulated string header failure")
            return real_u16(buf_, off)

        monkeypatch.setattr(pvi, "_u16", fake_u16)

        result = pvi._decode_string_file_info(inner, 0, len(inner))

        # The StringTable should have been entered (call 1 succeeded) but the
        # String entry header read failed (call 2 raised).
        assert len(result["tables"]) == 1
        assert "string_header" in result["tables"][0]["errors"]

    # ---- Line 269-270: string_length malformation ----

    def test_decode_string_file_info_flags_string_length_too_small(self):
        """
        Cover: s_len < 6 branch in String entry parsing.

        Build a StringTable whose body contains a String header claiming
        wLength = 2, which is less than the 6-byte minimum.
        """
        # StringTable header: wLength placeholder, wValueLength=0, wType=1
        # Followed by key "040904B0" NUL-terminated UTF-16LE, then a malformed
        # String header with wLength = 2.
        st_key = _utf16_sz("040904B0")
        st_header = struct.pack("<HHH", 0, 0, 1) + st_key
        st_header = _pad4(st_header)

        bad_string = struct.pack("<HHH", 2, 0, 1)  # wLength=2 < 6
        bad_string = _pad4(bad_string)

        st_body = st_header + bad_string
        st_body = _pad4(st_body)
        st = struct.pack("<H", len(st_body)) + st_body[2:]

        result = _decode_string_file_info(st, 0, len(st))
        assert "string_length" in result["tables"][0]["errors"]

    # ---- Line 277: empty value branch (val_end <= val_start) ----

    def test_decode_string_with_empty_value(self):
        """
        Cover: sv = "" branch when a String entry has no value bytes.
        """
        # String with key "EmptyKey" and zero-length value.
        # wValueLength = 0 (no value chars), key followed by no value bytes.
        key = _utf16_sz("EmptyKey")
        header = struct.pack("<HHH", 0, 0, 1) + key
        header_padded = _pad4(header)
        full = header_padded
        full = _pad4(full)
        string_entry = struct.pack("<H", len(full)) + full[2:]

        # Wrap in a StringTable
        st_key = _utf16_sz("040904B0")
        st_header = struct.pack("<HHH", 0, 0, 1) + st_key
        st_header = _pad4(st_header)
        st_body = st_header + string_entry
        st_body = _pad4(st_body)
        st = struct.pack("<H", len(st_body)) + st_body[2:]

        result = _decode_string_file_info(st, 0, len(st))
        assert result["tables"]
        table = result["tables"][0]
        assert table["strings"].get("EmptyKey") == ""

    # ---- Line 295-297: VarFileInfo header struct.error ----

    def test_decode_var_file_info_handles_struct_error_in_header(self, monkeypatch):
        """
        Cover: except struct.error in _decode_var_file_info var header read.
        """
        import iocx.parsers.pe_version_info as pvi

        buf = b"\x10\x00" + b"\x00" * 100

        def fake_u16(buf_, off):
            raise struct.error("simulated var_header failure")

        monkeypatch.setattr(pvi, "_u16", fake_u16)

        result = pvi._decode_var_file_info(buf, 0, 50)
        assert "var_header" in result["errors"]

    # ---- Line 315-317: translation unpack struct.error ----

    def test_decode_var_file_info_handles_translation_unpack_failure(self, monkeypatch):
        """
        Cover: except struct.error when struct.unpack_from raises on a
        translation entry inside _decode_var_file_info.
        """
        import iocx.parsers.pe_version_info as pvi

        # Build a well-formed VarFileInfo wrapper with one Translation entry.
        vfi = _build_var_file_info([("Translation", [(0x0409, 0x04B0)])])

        real_unpack_from = struct.unpack_from

        def fake_unpack_from(fmt, buf_, offset=0):
            if fmt == "<HH":
                raise struct.error("simulated translation unpack failure")
            return real_unpack_from(fmt, buf_, offset)

        monkeypatch.setattr(pvi.struct, "unpack_from", fake_unpack_from)

        # We need to call into the var-file-info decoder. Find the body of
        # the VarFileInfo and the Var inside it.
        # Skip VarFileInfo header (6 bytes + key + pad) and Var header
        # (6 bytes + key + pad) to position at the translation array.
        # Easiest: decode the full envelope.
        envelope = _build_vs_versioninfo(ffi=_build_ffi(), var_file_info=vfi)
        out = pvi._decode_vs_versioninfo(envelope)

        # The translation_unpack error appears inside the Var's errors list
        vfi_out = out["var_file_info"][0]
        var = vfi_out["vars"][0]
        # Either the Var's parent or the translation array failed to populate
        assert "translation_unpack" in vfi_out["errors"] or var["translations"] == []
