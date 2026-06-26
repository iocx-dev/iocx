# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.parser_exports.

Strategy:
- Decoder tests build export directory byte buffers directly via helpers.
- Locator and entry-point tests use a minimal duck-typed fake-pe object.
- Determinism tests assert byte-for-byte stable output across repeated runs.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

import pytest

from iocx.parsers.pe_exports import (
    build_export_structure,
    _decode_export_directory,
    _is_valid_export_name,
    _locate_export_directory,
    _read_asciiz,
    _read_dword_array,
    _read_word_array,
    _EXPORT_DIRECTORY_SIZE,
)


# =================================================================
# Byte-level builders
# =================================================================

def _build_export_directory_header(
    characteristics: int = 0,
    timedatestamp: int = 0,
    major_version: int = 0,
    minor_version: int = 0,
    name_rva: int = 0,
    base: int = 1,
    num_functions: int = 0,
    num_names: int = 0,
    addr_functions: int = 0,
    addr_names: int = 0,
    addr_name_ordinals: int = 0,
) -> bytes:
    """Build the 40-byte IMAGE_EXPORT_DIRECTORY structure."""
    return struct.pack(
        "<II HH IIIIIII",
        characteristics, timedatestamp,
        major_version, minor_version,
        name_rva, base,
        num_functions, num_names,
        addr_functions, addr_names, addr_name_ordinals,
    )


def _pack_dwords(values: List[int]) -> bytes:
    return b"".join(struct.pack("<I", v) for v in values)


def _pack_words(values: List[int]) -> bytes:
    return b"".join(struct.pack("<H", v) for v in values)


def _asciiz(s: str) -> bytes:
    return s.encode("ascii") + b"\x00"


# =================================================================
# Fake pe object
# =================================================================

class _FakeDataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _FakeOptHdr:
    def __init__(self, export_dir: Optional[_FakeDataDir]):
        # Index 0 is IMAGE_DIRECTORY_ENTRY_EXPORT
        self.DATA_DIRECTORY = [export_dir]


class _FakePE:
    """
    Minimal duck-typed pe object exposing only what the parser uses:
    OPTIONAL_HEADER.DATA_DIRECTORY[0] and get_data(rva, size).
    """
    def __init__(
        self,
        export_rva: int = 0,
        export_size: int = 0,
        data_by_rva: Optional[Dict[int, bytes]] = None,
        raise_on_get_data: Optional[Exception] = None,
        raise_for_rva: Optional[int] = None,
    ):
        if export_rva == 0 and export_size == 0:
            self.OPTIONAL_HEADER = _FakeOptHdr(None)
        else:
            self.OPTIONAL_HEADER = _FakeOptHdr(
                _FakeDataDir(export_rva, export_size)
            )
        self._data = data_by_rva or {}
        self._raise = raise_on_get_data
        self._raise_for_rva = raise_for_rva

    def get_data(self, rva: int, size: int) -> bytes:
        if self._raise is not None:
            if self._raise_for_rva is None or self._raise_for_rva == rva:
                raise self._raise
        if rva not in self._data:
            raise ValueError(f"no fixture data at rva {rva}")
        return self._data[rva][:size]


# =================================================================
# _locate_export_directory
# =================================================================

class TestLocator:

    def test_no_data_directory_returns_none(self):
        pe = type("FakePE", (), {})()
        assert _locate_export_directory(pe) is None

    def test_index_error_returns_none(self):
        class _PE:
            class OPTIONAL_HEADER:
                DATA_DIRECTORY = []
        assert _locate_export_directory(_PE) is None

    def test_attribute_error_returns_none(self):
        class _PE:
            class OPTIONAL_HEADER:
                pass
        assert _locate_export_directory(_PE) is None

    def test_zero_rva_returns_none(self):
        pe = _FakePE(export_rva=0, export_size=100)
        assert _locate_export_directory(pe) is None

    def test_zero_size_returns_none(self):
        pe = _FakePE(export_rva=0x1000, export_size=0)
        assert _locate_export_directory(pe) is None

    def test_valid_directory_returns_rva_size(self):
        pe = _FakePE(export_rva=0x1000, export_size=200)
        assert _locate_export_directory(pe) == (0x1000, 200)

    def test_type_error_in_int_cast_returns_none(self):
        class _BadDir:
            VirtualAddress = "not an int"
            Size = 100
        class _PE:
            class OPTIONAL_HEADER:
                DATA_DIRECTORY = [_BadDir()]
        assert _locate_export_directory(_PE) is None


# =================================================================
# _decode_export_directory
# =================================================================

class TestDecodeExportDirectory:

    def test_valid_header_decoded(self):
        header = _build_export_directory_header(
            characteristics=0,
            timedatestamp=0xDEADBEEF,
            major_version=1,
            minor_version=2,
            name_rva=0x1000,
            base=1,
            num_functions=5,
            num_names=3,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        out = _decode_export_directory(header)
        assert out is not None
        assert out["TimeDateStamp"] == 0xDEADBEEF
        assert out["MajorVersion"] == 1
        assert out["MinorVersion"] == 2
        assert out["Base"] == 1
        assert out["NumberOfFunctions"] == 5
        assert out["NumberOfNames"] == 3
        assert out["AddressOfFunctions"] == 0x1100
        assert out["AddressOfNames"] == 0x1200
        assert out["AddressOfNameOrdinals"] == 0x1300

    def test_too_short_returns_none(self):
        assert _decode_export_directory(b"\x00" * 39) is None

    def test_empty_returns_none(self):
        assert _decode_export_directory(b"") is None

    def test_all_zero_header_decoded(self):
        header = b"\x00" * _EXPORT_DIRECTORY_SIZE
        out = _decode_export_directory(header)
        assert out is not None
        assert out["NumberOfFunctions"] == 0
        assert out["Base"] == 0


# =================================================================
# Array readers
# =================================================================

class TestReadDwordArray:

    def test_zero_count_returns_empty_list(self):
        truncations = []
        result = _read_dword_array(_FakePE(), 0x1000, 0, truncations, "test")
        assert result == []
        assert truncations == []

    def test_zero_rva_flags_truncation_returns_none_list(self):
        truncations = []
        result = _read_dword_array(_FakePE(), 0, 3, truncations, "test")
        assert result == [None, None, None]
        assert truncations == ["test_rva_zero"]

    def test_read_failure_flags_truncation_returns_none_list(self):
        truncations = []
        pe = _FakePE(raise_on_get_data=RuntimeError("read failed"))
        result = _read_dword_array(pe, 0x1000, 3, truncations, "test")
        assert result == [None, None, None]
        assert truncations == ["test_read_failed"]

    def test_short_read_flags_truncation_with_partial_data(self):
        truncations = []
        # Caller wants 3 DWORDs (12 bytes) but only 6 bytes available
        pe = _FakePE(data_by_rva={0x1000: b"\x01\x00\x00\x00\x02\x00"})
        result = _read_dword_array(pe, 0x1000, 3, truncations, "test")
        assert result[0] == 1
        assert result[1] is None
        assert result[2] is None
        assert truncations == ["test_truncated"]

    def test_full_read_no_truncation(self):
        truncations = []
        pe = _FakePE(data_by_rva={
            0x1000: _pack_dwords([0x11, 0x22, 0x33]),
        })
        result = _read_dword_array(pe, 0x1000, 3, truncations, "test")
        assert result == [0x11, 0x22, 0x33]
        assert truncations == []


class TestReadWordArray:

    def test_zero_count_returns_empty(self):
        truncations = []
        result = _read_word_array(_FakePE(), 0x1000, 0, truncations, "test")
        assert result == []

    def test_zero_rva_flags_truncation(self):
        truncations = []
        result = _read_word_array(_FakePE(), 0, 2, truncations, "test")
        assert result == [None, None]
        assert truncations == ["test_rva_zero"]

    def test_full_read(self):
        truncations = []
        pe = _FakePE(data_by_rva={0x1000: _pack_words([1, 2, 3])})
        result = _read_word_array(pe, 0x1000, 3, truncations, "test")
        assert result == [1, 2, 3]

    def test_short_read_partial_data(self):
        truncations = []
        pe = _FakePE(data_by_rva={0x1000: b"\x01\x00"})  # 1 WORD only
        result = _read_word_array(pe, 0x1000, 3, truncations, "test")
        assert result[0] == 1
        assert result[1] is None
        assert result[2] is None
        assert truncations == ["test_truncated"]

    def test_read_failure(self):
        truncations = []
        pe = _FakePE(raise_on_get_data=RuntimeError("nope"))
        result = _read_word_array(pe, 0x1000, 2, truncations, "test")
        assert result == [None, None]
        assert truncations == ["test_read_failed"]


# =================================================================
# _read_asciiz
# =================================================================

class TestReadAsciiz:

    def test_zero_rva_returns_error(self):
        s, err = _read_asciiz(_FakePE(), 0, 100)
        assert s is None
        assert err == "rva_zero"

    def test_read_failure_returns_error(self):
        pe = _FakePE(raise_on_get_data=RuntimeError("nope"))
        s, err = _read_asciiz(pe, 0x1000, 100)
        assert s is None
        assert err == "read_failed"

    def test_empty_read_returns_error(self):
        pe = _FakePE(data_by_rva={0x1000: b""})
        s, err = _read_asciiz(pe, 0x1000, 100)
        assert s is None
        assert err == "empty_read"

    def test_unterminated_returns_error(self):
        pe = _FakePE(data_by_rva={0x1000: b"ABCDEF"})  # no NUL
        s, err = _read_asciiz(pe, 0x1000, 6)
        assert s is None
        assert err == "unterminated"

    def test_valid_ascii(self):
        pe = _FakePE(data_by_rva={0x1000: _asciiz("hello")})
        s, err = _read_asciiz(pe, 0x1000, 100)
        assert s == "hello"
        assert err is None

    def test_empty_string_with_terminator(self):
        pe = _FakePE(data_by_rva={0x1000: b"\x00"})
        s, err = _read_asciiz(pe, 0x1000, 100)
        assert s == ""
        assert err is None

    def test_non_ascii_returns_flag_with_replacement(self):
        pe = _FakePE(data_by_rva={0x1000: b"caf\xc3\xa9\x00"})  # UTF-8 café
        s, err = _read_asciiz(pe, 0x1000, 100)
        assert err == "non_ascii"
        assert s is not None
        assert "?" in s or "\ufffd" in s.encode("utf-8").decode("utf-8", errors="replace")

    def test_string_within_oversized_buffer(self):
        pe = _FakePE(data_by_rva={0x1000: _asciiz("X") + b"\xff" * 100})
        s, err = _read_asciiz(pe, 0x1000, 200)
        assert s == "X"
        assert err is None


# =================================================================
# _is_valid_export_name
# =================================================================

class TestIsValidExportName:

    @pytest.mark.parametrize("name,expected", [
        ("CreateFileW", True),
        ("_imp__foo", True),
        ("@ordinal_2", True),
        ("Foo Bar", True),  # space is 0x20, allowed
        ("!@#$%^&*()", True),  # all printable
        ("", False),
        ("Foo\x01Bar", False),
        ("Foo\x7fBar", False),
        ("Foo\x00Bar", False),
        ("café", False),  # non-ASCII
    ])
    def test_validation(self, name, expected):
        assert _is_valid_export_name(name) is expected


# =================================================================
# build_export_structure — full roundtrips
# =================================================================

class TestBuildExportStructure:

    def test_no_export_directory_returns_none(self):
        pe = _FakePE(export_rva=0, export_size=0)
        assert build_export_structure(pe) is None

    def test_header_read_failure_returns_empty_result(self):
        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            raise_on_get_data=RuntimeError("simulated"),
        )
        result = build_export_structure(pe)
        assert result is not None
        assert result["header"] is None
        assert "header_read_failed" in result["errors"]

    def test_short_header_flags_truncation(self):
        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            data_by_rva={0x1000: b"\x00" * 20},  # less than 40 bytes
        )
        result = build_export_structure(pe)
        assert result["header"] is None
        assert "export_directory_header" in result["truncations"]

    def test_unparseable_header(self, monkeypatch):
        """Force _decode_export_directory to return None even with sufficient bytes."""
        import iocx.parsers.pe_exports as pep

        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            data_by_rva={0x1000: b"\x00" * _EXPORT_DIRECTORY_SIZE},
        )
        monkeypatch.setattr(pep, "_decode_export_directory", lambda buf: None)
        result = build_export_structure(pe)
        assert result["header"] is None
        assert "header_unpack_failed" in result["errors"]

    def test_minimal_valid_export_table_with_one_named_function(self):
        # Layout:
        #   Header at 0x1000 (40 bytes)
        #   EAT at 0x1100 (1 dword, points to function at 0x2000)
        #   ENPT at 0x1200 (1 dword, points to name string)
        #   EOT at 0x1300 (1 word, EAT index 0)
        #   Name string at 0x1400 ("Foo\0")
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0x1400]),
                0x1300: _pack_words([0]),
                0x1400: _asciiz("Foo"),
            },
        )
        result = build_export_structure(pe)

        assert result is not None
        assert result["rva"] == 0x1000
        assert result["size"] == 200
        assert result["truncations"] == []
        assert result["errors"] == []
        assert len(result["functions"]) == 1
        assert len(result["name_pointers"]) == 1

        fn = result["functions"][0]
        assert fn["index"] == 0
        assert fn["ordinal"] == 1
        assert fn["address_rva"] == 0x2000
        assert fn["is_forwarder"] is False
        assert fn["name"] == "Foo"

        np = result["name_pointers"][0]
        assert np["index"] == 0
        assert np["name_rva"] == 0x1400
        assert np["ordinal_index"] == 0
        assert np["name"] == "Foo"
        assert np["name_valid"] is True
        assert np["errors"] == []

    def test_forwarder_detected_when_address_points_within_directory(self):
        # Address RVA falls within the export directory range,
        # indicating a forwarder per PE spec.
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=0,
            addr_functions=0x1100,
        )
        forwarder_rva = 0x1050  # within [0x1000, 0x1000 + 200)
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([forwarder_rva]),
                forwarder_rva: _asciiz("KERNEL32.LoadLibraryA"),
            },
        )
        result = build_export_structure(pe)
        fn = result["functions"][0]
        assert fn["is_forwarder"] is True
        assert fn["forwarder"] == "KERNEL32.LoadLibraryA"
        assert fn["forwarder_valid"] is True
        assert fn["address_rva"] == forwarder_rva

    def test_invalid_forwarder_format_flagged(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=0,
            addr_functions=0x1100,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x1050]),
                0x1050: _asciiz("NoDotInThisString"),
            },
        )
        result = build_export_structure(pe)
        fn = result["functions"][0]
        assert fn["is_forwarder"] is True
        assert fn["forwarder"] == "NoDotInThisString"
        assert fn["forwarder_valid"] is False

    def test_forwarder_with_ordinal_syntax_valid(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=0,
            addr_functions=0x1100,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x1050]),
                0x1050: _asciiz("KERNEL32.#42"),
            },
        )
        result = build_export_structure(pe)
        assert result["functions"][0]["forwarder_valid"] is True

    def test_name_pointer_with_zero_rva_flagged(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0]),  # name_rva = 0
                0x1300: _pack_words([0]),
            },
        )
        result = build_export_structure(pe)
        np = result["name_pointers"][0]
        assert "name_rva_zero" in np["errors"]
        assert np["name"] is None

    def test_name_pointer_with_unterminated_string_flagged(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0x1400]),
                0x1300: _pack_words([0]),
                0x1400: b"NoTerminator" * 100,  # no NUL within max scan
            },
        )
        result = build_export_structure(pe)
        np = result["name_pointers"][0]
        assert "unterminated" in np["errors"]

    def test_name_pointer_with_non_printable_name_flagged(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0x1400]),
                0x1300: _pack_words([0]),
                0x1400: b"Foo\x01Bar\x00",  # contains control char
            },
        )
        result = build_export_structure(pe)
        np = result["name_pointers"][0]
        assert "name_not_printable_ascii" in np["errors"]
        assert np["name_valid"] is False

    def test_ordinal_index_out_of_range_flagged(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=1,  # only 1 function
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0x1400]),
                0x1300: _pack_words([5]),  # ordinal_index=5, but only 1 function
                0x1400: _asciiz("Foo"),
            },
        )
        result = build_export_structure(pe)
        np = result["name_pointers"][0]
        assert "ordinal_index_out_of_range" in np["errors"]

    def test_eat_truncation_propagates(self):
        # Declare 5 functions but only provide bytes for 2
        header = _build_export_directory_header(
            base=1,
            num_functions=5,
            num_names=0,
            addr_functions=0x1100,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000, 0x2100]),  # only 2 of 5
            },
        )
        result = build_export_structure(pe)
        assert "eat_truncated" in result["truncations"]
        assert len(result["functions"]) == 5
        assert result["functions"][0]["address_rva"] == 0x2000
        assert result["functions"][2]["address_rva"] is None

    def test_unused_eat_slots_legitimate(self):
        # EAT entry of 0 is "this ordinal slot unused" per PE spec
        header = _build_export_directory_header(
            base=1,
            num_functions=3,
            num_names=0,
            addr_functions=0x1100,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000, 0, 0x2200]),
            },
        )
        result = build_export_structure(pe)
        assert result["functions"][0]["address_rva"] == 0x2000
        assert result["functions"][1]["address_rva"] == 0
        assert result["functions"][2]["address_rva"] == 0x2200

    def test_name_resolution_joins_eat_with_enpt(self):
        # Function at EAT index 2 has a name; functions 0, 1 don't.
        header = _build_export_directory_header(
            base=1,
            num_functions=3,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000, 0x2100, 0x2200]),
                0x1200: _pack_dwords([0x1400]),
                0x1300: _pack_words([2]),  # name points to EAT index 2
                0x1400: _asciiz("NamedFunc"),
            },
        )
        result = build_export_structure(pe)
        assert result["functions"][0]["name"] is None
        assert result["functions"][1]["name"] is None
        assert result["functions"][2]["name"] == "NamedFunc"

    def test_empty_export_table(self):
        # Header declares zero functions and zero names
        header = _build_export_directory_header(base=1)
        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            data_by_rva={0x1000: header},
        )
        result = build_export_structure(pe)
        assert result["functions"] == []
        assert result["name_pointers"] == []
        assert result["truncations"] == []

    def test_name_pointer_with_truncated_enpt_flags_name_rva_missing(self):
        """
        Cover line 350: when ENPT is truncated, _build_name_pointers consumes
        a None from enpt and tags name_rva_missing.
        """
        header = _build_export_directory_header(
            base=1,
            num_functions=1,
            num_names=3,  # declared 3 names
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000]),
                0x1200: _pack_dwords([0x1400]),       # only 1 of 3 DWORDs
                0x1300: _pack_words([0, 0, 0]),       # EOT is full
                0x1400: _asciiz("Foo"),
            },
        )
        result = build_export_structure(pe)

        # Truncation should be flagged on the ENPT
        assert "enpt_truncated" in result["truncations"]

        # Entries 1 and 2 should carry name_rva_missing (their enpt[i] is None)
        assert "name_rva_missing" in result["name_pointers"][1]["errors"]
        assert "name_rva_missing" in result["name_pointers"][2]["errors"]

        # Entry 0 is well-formed
        assert result["name_pointers"][0]["name"] == "Foo"

    def test_name_pointer_with_truncated_eot_flags_ordinal_index_missing(self):
        """
        Cover line 364: when EOT is truncated, _build_name_pointers consumes
        a None from eot and tags ordinal_index_missing.
        """
        header = _build_export_directory_header(
            base=1,
            num_functions=3,
            num_names=3,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        pe = _FakePE(
            export_rva=0x1000,
            export_size=200,
            data_by_rva={
                0x1000: header,
                0x1100: _pack_dwords([0x2000, 0x2100, 0x2200]),
                0x1200: _pack_dwords([0x1400, 0x1404, 0x1408]),
                0x1300: _pack_words([0]),              # only 1 of 3 WORDs
                0x1400: _asciiz("Foo"),
                0x1404: _asciiz("Bar"),
                0x1408: _asciiz("Baz"),
            },
        )
        result = build_export_structure(pe)

        assert "eot_truncated" in result["truncations"]
        assert "ordinal_index_missing" in result["name_pointers"][1]["errors"]
        assert "ordinal_index_missing" in result["name_pointers"][2]["errors"]
        assert result["name_pointers"][0]["ordinal_index"] == 0


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    REQUIRED_KEYS = {
        "rva", "size", "header", "functions", "name_pointers",
        "truncations", "errors",
    }

    def test_successful_decode_has_all_required_keys(self):
        header = _build_export_directory_header(base=1)
        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            data_by_rva={0x1000: header},
        )
        result = build_export_structure(pe)
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_lists_are_lists_even_when_empty(self):
        header = _build_export_directory_header(base=1)
        pe = _FakePE(
            export_rva=0x1000,
            export_size=100,
            data_by_rva={0x1000: header},
        )
        result = build_export_structure(pe)
        assert isinstance(result["functions"], list)
        assert isinstance(result["name_pointers"], list)
        assert isinstance(result["truncations"], list)
        assert isinstance(result["errors"], list)


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_parse_produces_identical_output(self):
        header = _build_export_directory_header(
            base=1,
            num_functions=2,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        data = {
            0x1000: header,
            0x1100: _pack_dwords([0x2000, 0x2100]),
            0x1200: _pack_dwords([0x1400]),
            0x1300: _pack_words([0]),
            0x1400: _asciiz("Foo"),
        }

        results = []
        for _ in range(20):
            pe = _FakePE(
                export_rva=0x1000,
                export_size=200,
                data_by_rva=dict(data),
            )
            results.append(build_export_structure(pe))

        for r in results[1:]:
            assert r == results[0]

    def test_malformed_input_deterministic(self):
        # Truncated EAT, non-ASCII name, out-of-range ordinal
        header = _build_export_directory_header(
            base=1,
            num_functions=5,
            num_names=1,
            addr_functions=0x1100,
            addr_names=0x1200,
            addr_name_ordinals=0x1300,
        )
        data = {
            0x1000: header,
            0x1100: _pack_dwords([0x2000]),  # only 1 of 5
            0x1200: _pack_dwords([0x1400]),
            0x1300: _pack_words([99]),
            0x1400: b"caf\xc3\xa9\x00",
        }

        results = []
        for _ in range(20):
            pe = _FakePE(
                export_rva=0x1000,
                export_size=200,
                data_by_rva=dict(data),
            )
            results.append(build_export_structure(pe))

        for r in results[1:]:
            assert r == results[0]
