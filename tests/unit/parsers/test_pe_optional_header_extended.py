# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Tests the _parse_optional_header and _parse_header routines plus the
constants module. Uses minimal duck-typed pe / OPTIONAL_HEADER / FILE_HEADER
objects to isolate parser logic from pefile's actual struct behaviour.

Coverage targets:
- Constants module: tables and derived mask
- DLL characteristics decoding (empty, single, multi, unknown bits)
- Subsystem name resolution (known, unknown, edge values)
- Field extraction (existing fields preserved, new fields populated)
- Missing-field handling (None for new fields, 0 for existing)
- Determinism (repeated parse produces identical output)
- JSON-safety (output round-trips through json.dumps)
- Output contract (key set matches schema)
"""

from __future__ import annotations
import json
import pytest
from typing import Any, Dict, List, Optional
from iocx.parsers.pe_constants import (
    DLL_CHARACTERISTICS_FLAGS,
    DLL_CHARACTERISTICS_KNOWN_MASK,
    SUBSYSTEM_NAMES,
)
from iocx.parsers.pe_parser import _parse_header, _parse_optional_header


# =================================================================
# Test doubles
# =================================================================

class _FakeOH:
    """
    Minimal duck-typed OPTIONAL_HEADER. Any field that's set on the instance
    will be returned by getattr; any field that's not set returns the
    getattr default (which is what _parse_optional_header relies on).
    """
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakeFH:
    """Minimal duck-typed FILE_HEADER."""
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePE:
    """Minimal duck-typed pe object."""
    def __init__(self, optional_header=None, file_header=None):
        if optional_header is not None:
            self.OPTIONAL_HEADER = optional_header
        if file_header is not None:
            self.FILE_HEADER = file_header


# Common builder for a fully-populated OH covering all extracted fields
def _full_oh(**overrides) -> _FakeOH:
    defaults = dict(
        SectionAlignment=4096,
        FileAlignment=512,
        SizeOfImage=24576,
        SizeOfHeaders=1024,
        MajorLinkerVersion=14,
        MinorLinkerVersion=42,
        MajorOperatingSystemVersion=6,
        MinorOperatingSystemVersion=0,
        MajorSubsystemVersion=6,
        MinorSubsystemVersion=0,
        Subsystem=3,
        DllCharacteristics=0x4160,
        Win32VersionValue=0,
        LoaderFlags=0,
        SizeOfStackReserve=0x100000,
        SizeOfStackCommit=0x1000,
        SizeOfHeapReserve=0x100000,
        SizeOfHeapCommit=0x1000,
        AddressOfEntryPoint=0x1000,
        ImageBase=0x140000000,
    )
    defaults.update(overrides)
    return _FakeOH(**defaults)


def _full_fh(**overrides) -> _FakeFH:
    defaults = dict(
        TimeDateStamp=1700000000,
        Machine=0x8664,
        Characteristics=0x22,
    )
    defaults.update(overrides)
    return _FakeFH(**defaults)


# =================================================================
# Constants module
# =================================================================

class TestConstants:

    def test_subsystem_names_contains_well_known_values(self):
        assert SUBSYSTEM_NAMES[3] == "WINDOWS_CUI"
        assert SUBSYSTEM_NAMES[2] == "WINDOWS_GUI"
        assert SUBSYSTEM_NAMES[1] == "NATIVE"
        assert SUBSYSTEM_NAMES[10] == "EFI_APPLICATION"

    def test_dll_characteristics_flags_contains_well_known_bits(self):
        assert DLL_CHARACTERISTICS_FLAGS[0x0040] == "DYNAMIC_BASE"
        assert DLL_CHARACTERISTICS_FLAGS[0x0100] == "NX_COMPAT"
        assert DLL_CHARACTERISTICS_FLAGS[0x4000] == "GUARD_CF"
        assert DLL_CHARACTERISTICS_FLAGS[0x8000] == "TERMINAL_SERVER_AWARE"

    def test_subsystem_table_covers_pe_spec(self):
        """The SUBSYSTEM_NAMES table covers the well-known IMAGE_SUBSYSTEM_* values."""
        required_subsystems = {0, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16}
        assert required_subsystems.issubset(set(SUBSYSTEM_NAMES.keys()))

    def test_known_mask_covers_all_listed_bits(self):
        expected_mask = 0
        for bit in DLL_CHARACTERISTICS_FLAGS:
            expected_mask |= bit
        assert DLL_CHARACTERISTICS_KNOWN_MASK == expected_mask

    def test_known_mask_is_subset_of_u16(self):
        # All defined DLL characteristics fit in a u16
        assert DLL_CHARACTERISTICS_KNOWN_MASK <= 0xFFFF

    def test_subsystem_names_has_no_duplicate_values(self):
        values = list(SUBSYSTEM_NAMES.values())
        assert len(values) == len(set(values))

    def test_dll_characteristics_flags_has_no_duplicate_names(self):
        names = list(DLL_CHARACTERISTICS_FLAGS.values())
        assert len(names) == len(set(names))


# =================================================================
# _parse_optional_header — top-level behaviour
# =================================================================

class TestParseOptionalHeaderTopLevel:

    def test_returns_empty_dict_when_optional_header_missing(self):
        pe = _FakePE()
        opt, out = _parse_optional_header(pe)
        assert opt is None
        assert out == {}

    def test_returns_optional_header_object_unchanged(self):
        oh = _full_oh()
        pe = _FakePE(optional_header=oh)
        opt, out = _parse_optional_header(pe)
        assert opt is oh

    def test_returns_dict_with_expected_keys(self):
        oh = _full_oh()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        expected_keys = {
            # Existing fields
            "section_alignment", "file_alignment", "size_of_image",
            "size_of_headers", "linker_version", "os_version",
            "subsystem_version",
            # New: DLL characteristics
            "dll_characteristics", "dll_characteristics_flags",
            "dll_characteristics_unknown_bits",
            # New: deprecated/reserved DWORDs
            "win32_version_value", "loader_flags",
            # New: stack/heap sizing
            "stack_reserve_size", "stack_commit_size",
            "heap_reserve_size", "heap_commit_size",
        }
        assert set(out.keys()) == expected_keys


# =================================================================
# Existing fields — backward compatibility
# =================================================================

class TestExistingFieldsBackwardCompatible:

    def test_existing_fields_match_full_oh(self):
        oh = _full_oh()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["section_alignment"] == 4096
        assert out["file_alignment"] == 512
        assert out["size_of_image"] == 24576
        assert out["size_of_headers"] == 1024
        assert out["linker_version"] == "14.42"
        assert out["os_version"] == "6.0"
        assert out["subsystem_version"] == "6.0"

    def test_existing_fields_default_to_zero_when_missing(self):
        # The existing parser uses 0 as the getattr default; preserved.
        oh = _FakeOH()  # no fields set
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["section_alignment"] == 0
        assert out["file_alignment"] == 0
        assert out["size_of_image"] == 0
        assert out["size_of_headers"] == 0
        assert out["linker_version"] == "0.0"
        assert out["os_version"] == "0.0"
        assert out["subsystem_version"] == "0.0"


# =================================================================
# New fields — extraction
# =================================================================

class TestNewFieldsExtraction:

    def test_dll_characteristics_raw_value(self):
        oh = _full_oh(DllCharacteristics=0x4140)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics"] == 0x4140

    def test_dll_characteristics_decoded_flags(self):
        # 0x4140 = DYNAMIC_BASE (0x0040) | NX_COMPAT (0x0100) | GUARD_CF (0x4000)
        oh = _full_oh(DllCharacteristics=0x4140)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics_flags"] == [
            "DYNAMIC_BASE", "NX_COMPAT", "GUARD_CF"
        ]

    def test_dll_characteristics_empty_when_zero(self):
        oh = _full_oh(DllCharacteristics=0)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics"] == 0
        assert out["dll_characteristics_flags"] == []
        assert out["dll_characteristics_unknown_bits"] is None

    def test_dll_characteristics_unknown_bits(self):
        # 0x10000 is outside the known mask
        oh = _full_oh(DllCharacteristics=0x10040)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics_flags"] == ["DYNAMIC_BASE"]
        assert out["dll_characteristics_unknown_bits"] == "0x10000"

    def test_dll_characteristics_all_known_bits_no_unknown(self):
        # Every known bit set should produce no unknown_bits report
        oh = _full_oh(DllCharacteristics=DLL_CHARACTERISTICS_KNOWN_MASK)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert len(out["dll_characteristics_flags"]) == len(DLL_CHARACTERISTICS_FLAGS)
        assert out["dll_characteristics_unknown_bits"] is None

    def test_dll_characteristics_only_unknown_bits(self):
        oh = _full_oh(DllCharacteristics=0x10000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics_flags"] == []
        assert out["dll_characteristics_unknown_bits"] == "0x10000"

    def test_dll_characteristics_missing_returns_none(self):
        oh = _FakeOH()  # DllCharacteristics not set
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics"] is None
        assert out["dll_characteristics_flags"] is None
        assert out["dll_characteristics_unknown_bits"] is None

    def test_win32_version_value_extracted(self):
        oh = _full_oh(Win32VersionValue=0x1234)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["win32_version_value"] == 0x1234

    def test_win32_version_value_missing_returns_none(self):
        oh = _FakeOH()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["win32_version_value"] is None

    def test_loader_flags_extracted(self):
        oh = _full_oh(LoaderFlags=0xCAFE)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["loader_flags"] == 0xCAFE

    def test_loader_flags_missing_returns_none(self):
        oh = _FakeOH()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["loader_flags"] is None

    def test_stack_reserve_size_extracted(self):
        oh = _full_oh(SizeOfStackReserve=0x200000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["stack_reserve_size"] == 0x200000

    def test_stack_commit_size_extracted(self):
        oh = _full_oh(SizeOfStackCommit=0x2000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["stack_commit_size"] == 0x2000

    def test_heap_reserve_size_extracted(self):
        oh = _full_oh(SizeOfHeapReserve=0x300000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["heap_reserve_size"] == 0x300000

    def test_heap_commit_size_extracted(self):
        oh = _full_oh(SizeOfHeapCommit=0x3000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["heap_commit_size"] == 0x3000

    def test_stack_heap_sizes_missing_return_none(self):
        oh = _FakeOH()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["stack_reserve_size"] is None
        assert out["stack_commit_size"] is None
        assert out["heap_reserve_size"] is None
        assert out["heap_commit_size"] is None

    def test_pe32_plus_64bit_sizes(self):
        # PE32+ binaries use 64-bit values; ensure they pass through
        oh = _full_oh(SizeOfStackReserve=0x100000000)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["stack_reserve_size"] == 0x100000000


# =================================================================
# DLL characteristics flag ordering
# =================================================================

class TestDllCharacteristicsOrdering:

    def test_flags_returned_in_bit_position_order(self):
        # 0xC1A0 = HIGH_ENTROPY_VA (0x0020) | DYNAMIC_BASE (0x0040)
        #       | NX_COMPAT (0x0100) | GUARD_CF (0x4000)
        #       | TERMINAL_SERVER_AWARE (0x8000)
        oh = _full_oh(DllCharacteristics=0xC160)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics_flags"] == [
            "HIGH_ENTROPY_VA",
            "DYNAMIC_BASE",
            "NX_COMPAT",
            "GUARD_CF",
            "TERMINAL_SERVER_AWARE",
        ]

    def test_ordering_deterministic_across_runs(self):
        oh = _full_oh(DllCharacteristics=0x4160)
        pe = _FakePE(optional_header=oh)
        results = []
        for _ in range(20):
            _, out = _parse_optional_header(pe)
            results.append(out["dll_characteristics_flags"])
        assert all(r == results[0] for r in results)


# =================================================================
# _parse_header
# =================================================================

class TestParseHeader:

    def test_full_header_extraction(self):
        oh = _full_oh()
        fh = _full_fh()
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert out["entry_point"] == 0x1000
        assert out["image_base"] == 0x140000000
        assert out["subsystem"] == 3
        assert out["subsystem_name"] == "WINDOWS_CUI"
        assert out["timestamp"] == 1700000000
        assert out["machine"] == 0x8664
        assert out["characteristics"] == 0x22

    def test_subsystem_name_for_all_known_values(self):
        for subsystem_id, expected_name in SUBSYSTEM_NAMES.items():
            oh = _full_oh(Subsystem=subsystem_id)
            fh = _full_fh()
            pe = _FakePE(optional_header=oh, file_header=fh)
            out = _parse_header(pe, oh)
            assert out["subsystem"] == subsystem_id
            assert out["subsystem_name"] == expected_name

    def test_subsystem_name_none_for_unknown_value(self):
        oh = _full_oh(Subsystem=99)
        fh = _full_fh()
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert out["subsystem"] == 99
        assert out["subsystem_name"] is None

    def test_missing_optional_header_uses_zeros(self):
        fh = _full_fh()
        pe = _FakePE(file_header=fh)
        out = _parse_header(pe, None)
        assert out["entry_point"] == 0
        assert out["image_base"] == 0
        assert out["subsystem"] == 0
        # Subsystem 0 is UNKNOWN per the table
        assert out["subsystem_name"] == "UNKNOWN"
        assert out["timestamp"] == 1700000000

    def test_missing_file_header_uses_zeros(self):
        oh = _full_oh()
        pe = _FakePE(optional_header=oh)
        out = _parse_header(pe, oh)
        assert out["entry_point"] == 0x1000
        assert out["timestamp"] == 0
        assert out["machine"] == 0
        assert out["characteristics"] == 0

    def test_both_headers_missing(self):
        pe = _FakePE()
        out = _parse_header(pe, None)
        assert out == {
            "entry_point": 0,
            "image_base": 0,
            "subsystem": 0,
            "subsystem_name": "UNKNOWN",
            "timestamp": 0,
            "machine": 0,
            "machine_name": "UNKNOWN",
            "characteristics": 0,
        }

    def test_returns_expected_key_set(self):
        oh = _full_oh()
        fh = _full_fh()
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert set(out.keys()) == {
            "entry_point", "image_base", "subsystem", "subsystem_name",
            "timestamp", "machine", "machine_name", "characteristics",
        }

# =================================================================
# Win32VersionValue / Reserved1 fallback
# =================================================================
class TestWin32VersionExtraction:

    def test_win32_version_value_falls_back_to_reserved1(self):
        """Pefile uses Reserved1 for the deprecated Win32VersionValue field."""
        oh = _FakeOH(Reserved1=42)  # only Reserved1 is set
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["win32_version_value"] == 42


    def test_win32_version_value_prefers_explicit_field_when_present(self):
        """If both names are present, the explicit Win32VersionValue wins."""
        oh = _FakeOH(Win32VersionValue=99, Reserved1=42)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["win32_version_value"] == 99


    def test_win32_version_value_none_when_neither_present(self):
        oh = _FakeOH()  # neither Win32VersionValue nor Reserved1 set
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["win32_version_value"] is None

# =================================================================
# Machine names
# =================================================================
class TestMachineNames:

    def test_machine_names_contains_well_known_values(self):
        from iocx.parsers.pe_constants import MACHINE_NAMES
        assert MACHINE_NAMES[0x014C] == "I386"
        assert MACHINE_NAMES[0x8664] == "AMD64"
        assert MACHINE_NAMES[0xAA64] == "ARM64"
        assert MACHINE_NAMES[0x0200] == "IA64"

    def test_machine_name_for_unknown_returns_none(self):
        from iocx.parsers.pe_constants import MACHINE_NAMES
        assert MACHINE_NAMES.get(0x9999) is None

    def test_machine_zero_is_unknown(self):
        """0x0000 is IMAGE_FILE_MACHINE_UNKNOWN per spec."""
        from iocx.parsers.pe_constants import MACHINE_NAMES
        assert MACHINE_NAMES[0x0000] == "UNKNOWN"

    def test_machine_names_no_duplicate_values(self):
        from iocx.parsers.pe_constants import MACHINE_NAMES
        values = list(MACHINE_NAMES.values())
        assert len(values) == len(set(values))

    def test_machine_name_decoded_in_header(self):
        oh = _full_oh()
        fh = _full_fh(Machine=0x8664)
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert out["machine"] == 0x8664
        assert out["machine_name"] == "AMD64"

    def test_machine_name_none_for_unknown_machine(self):
        oh = _full_oh()
        fh = _full_fh(Machine=0x9999)
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert out["machine"] == 0x9999
        assert out["machine_name"] is None

    def test_machine_name_zero_is_unknown(self):
        """machine=0 explicitly decodes to 'UNKNOWN' per spec."""
        oh = _full_oh()
        fh = _full_fh(Machine=0)
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        assert out["machine"] == 0
        assert out["machine_name"] == "UNKNOWN"

# =================================================================
# JSON safety
# =================================================================

class TestJsonSafety:

    def test_optional_header_output_serializes(self):
        oh = _full_oh()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        json.dumps(out)  # must not raise

    def test_optional_header_with_missing_fields_serializes(self):
        oh = _FakeOH()
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        json.dumps(out)

    def test_header_output_serializes(self):
        oh = _full_oh()
        fh = _full_fh()
        pe = _FakePE(optional_header=oh, file_header=fh)
        out = _parse_header(pe, oh)
        json.dumps(out)

    def test_header_with_missing_fields_serializes(self):
        pe = _FakePE()
        out = _parse_header(pe, None)
        json.dumps(out)

    def test_unknown_bits_as_string_serializes_cleanly(self):
        oh = _full_oh(DllCharacteristics=0x10040)
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        result = json.dumps(out)
        assert "0x10000" in result


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_optional_header_parse_identical(self):
        oh = _full_oh(DllCharacteristics=0x4160)
        pe = _FakePE(optional_header=oh)
        results = []
        for _ in range(20):
            _, out = _parse_optional_header(pe)
            results.append(out)
        for r in results[1:]:
            assert r == results[0]

    def test_repeated_header_parse_identical(self):
        oh = _full_oh()
        fh = _full_fh()
        pe = _FakePE(optional_header=oh, file_header=fh)
        results = [_parse_header(pe, oh) for _ in range(20)]
        for r in results[1:]:
            assert r == results[0]

    def test_optional_header_with_missing_fields_deterministic(self):
        oh = _FakeOH()
        pe = _FakePE(optional_header=oh)
        results = []
        for _ in range(20):
            _, out = _parse_optional_header(pe)
            results.append(out)
        for r in results[1:]:
            assert r == results[0]


# =================================================================
# Conservative field handling
# =================================================================

class TestConservativeFieldHandling:

    def test_individual_field_missing_does_not_break_others(self):
        # Construct an OH missing only SizeOfStackReserve; other fields
        # should populate normally
        oh = _FakeOH(
            SectionAlignment=4096,
            Subsystem=3,
            DllCharacteristics=0x4140,
            # SizeOfStackReserve deliberately not set
            SizeOfStackCommit=0x1000,
            SizeOfHeapReserve=0x100000,
            SizeOfHeapCommit=0x1000,
        )
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["section_alignment"] == 4096
        assert out["dll_characteristics"] == 0x4140
        assert out["stack_commit_size"] == 0x1000
        assert out["heap_reserve_size"] == 0x100000
        assert out["stack_reserve_size"] is None  # missing → None

    def test_partial_field_failures_do_not_propagate(self):
        # All security-related new fields missing, but stack/heap present
        oh = _FakeOH(
            SectionAlignment=4096,
            SizeOfStackReserve=0x100000,
            SizeOfStackCommit=0x1000,
        )
        pe = _FakePE(optional_header=oh)
        _, out = _parse_optional_header(pe)
        assert out["dll_characteristics"] is None
        assert out["dll_characteristics_flags"] is None
        assert out["dll_characteristics_unknown_bits"] is None
        assert out["loader_flags"] is None
        assert out["stack_reserve_size"] == 0x100000  # populated
