# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for pe_exception.build_exception_structure.

Strategy:
- The parser touches pefile only via three surfaces: OPTIONAL_HEADER.
  DATA_DIRECTORY[3], FILE_HEADER.Machine, and pe.get_data(rva, length).
  FakePE below implements exactly those, over a flat {rva: bytes} map, so
  every branch is driven from real bytes without building a PE on disk.
- Tests assert on the documented output contract: the top-level key set, the
  arch/entry_size routing, the per-entry dicts, and the tombstone tags in
  `errors` / `truncations`.

get_data semantics: pefile returns a SHORT buffer when a read runs past the
end of a section rather than raising, and raises for an unmapped RVA. FakePE
reproduces both, because the parser distinguishes them
(exception_entry_read_failed vs exception_entry_truncated).

Contract note: these tombstone tags are the parser's half of a contract with
validators.exception_table, whose _ENTRY_ERROR_PRIORITY and
_UNWIND_ERROR_PRIORITY lists consume them. TestValidatorContract at the end
pins the exact vocabulary so the two cannot drift apart silently.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

import pytest

from iocx.parsers.pe_exception import build_exception_structure


# Machine values the parser routes on
M_I386 = 0x014C
M_IA64 = 0x0200
M_ARM = 0x01C0
M_ARMNT = 0x01C4
M_AMD64 = 0x8664
M_ARM64 = 0xAA64
M_ARM64EC = 0xA641

DIR_RVA = 0x1000
UW_RVA = 0x3000


# =================================================================
# Test doubles
# =================================================================

class _Dir:
    def __init__(self, va, size):
        self.VirtualAddress = va
        self.Size = size


class _OptionalHeader:
    def __init__(self, dirs):
        self.DATA_DIRECTORY = dirs


class _FileHeader:
    def __init__(self, machine):
        self.Machine = machine


class FakePE:
    """
    Minimal pefile stand-in exposing only what the parser uses.

    `mem` is a flat {base_rva: bytes} map. get_data mirrors pefile: a read
    inside a mapped blob but running past its end returns a SHORT buffer; a
    read at an unmapped RVA raises.
    """

    def __init__(self, machine: Any = M_AMD64,
                 exc: Optional[tuple] = (DIR_RVA, 24),
                 mem: Optional[Dict[int, bytes]] = None,
                 dirs_len: int = 16,
                 omit_optional_header: bool = False,
                 omit_file_header: bool = False):
        dirs = [_Dir(0, 0) for _ in range(dirs_len)]
        if exc is not None and dirs_len > 3:
            dirs[3] = _Dir(*exc)
        if not omit_optional_header:
            self.OPTIONAL_HEADER = _OptionalHeader(dirs)
        if not omit_file_header:
            self.FILE_HEADER = _FileHeader(machine)
        self._mem = mem or {}

    def get_data(self, rva: int, length: int) -> bytes:
        for base, blob in self._mem.items():
            if base <= rva < base + len(blob):
                off = rva - base
                return blob[off:off + length]   # may be short, like pefile
        raise ValueError(f"unmapped rva 0x{rva:X}")


# =================================================================
# Byte builders
# =================================================================

def rf(begin: int, end: int, unwind: int) -> bytes:
    """AMD64 RUNTIME_FUNCTION: 3 x DWORD."""
    return struct.pack("<III", begin, end, unwind)


def arm_rec(begin: int, word1: int) -> bytes:
    """ARM(64) .pdata record: 2 x DWORD."""
    return struct.pack("<II", begin, word1)


def unwind_bytes(version: int = 1, flags: int = 0, prolog: int = 4,
                 count: int = 0, chain: Optional[tuple] = None) -> bytes:
    """
    UNWIND_INFO: byte0 = version(bits 2:0) | flags(bits 7:3), then prolog,
    count, frame; then the even-padded USHORT code array; then optionally a
    trailing RUNTIME_FUNCTION for the chained case.
    """
    b0 = (version & 0x07) | ((flags & 0x1F) << 3)
    out = bytes([b0, prolog & 0xFF, count & 0xFF, 0])
    padded = (count + 1) & ~1
    out += b"\x00" * (padded * 2)
    if chain is not None:
        out += struct.pack("<III", *chain)
    return out


def _control_table() -> bytes:
    """Two sorted amd64 entries, both pointing at a valid unwind blob."""
    return rf(0x2000, 0x2050, UW_RVA) + rf(0x2060, 0x20B0, UW_RVA)


def _amd64_pe(entries: bytes, size: Optional[int] = None,
              unwind: Optional[bytes] = None,
              unwind_rva: int = UW_RVA, **kw) -> FakePE:
    mem = {DIR_RVA: entries}
    if unwind is not None:
        mem[unwind_rva] = unwind
    return FakePE(machine=M_AMD64, exc=(DIR_RVA, size or len(entries)),
                  mem=mem, **kw)


def _first_unwind(unwind: bytes, unwind_rva: int = UW_RVA) -> Dict[str, Any]:
    """Decode a single entry pointing at `unwind`; return its unwind dict."""
    pe = _amd64_pe(rf(0x2000, 0x2050, unwind_rva), size=12,
                   unwind=unwind, unwind_rva=unwind_rva)
    return build_exception_structure(pe)["functions"][0]["unwind"]


# =================================================================
# Absence
# =================================================================

class TestAbsence:
    """Absence of an exception directory returns None - never an error."""

    def test_no_optional_header_returns_none(self):
        assert build_exception_structure(
            FakePE(omit_optional_header=True)) is None

    def test_short_directory_array_returns_none(self):
        """IndexError on DATA_DIRECTORY[3] is swallowed."""
        assert build_exception_structure(FakePE(dirs_len=3)) is None

    def test_zero_rva_returns_none(self):
        assert build_exception_structure(FakePE(exc=(0, 24))) is None

    def test_zero_size_returns_none(self):
        assert build_exception_structure(FakePE(exc=(DIR_RVA, 0))) is None

    def test_both_zero_returns_none(self):
        assert build_exception_structure(FakePE(exc=(0, 0))) is None

    def test_non_int_directory_fields_return_none(self):
        """A ValueError/TypeError from int() is swallowed."""
        assert build_exception_structure(
            FakePE(exc=("not-an-int", 24))) is None


# =================================================================
# Machine reading and arch routing
# =================================================================

class TestMachineAndArch:

    @pytest.mark.parametrize("machine,arch,entry_size", [
        (M_AMD64, "amd64", 12),
        (M_ARM64, "arm64", 8),
        (M_ARM64EC, "arm64", 8),   # ARM64EC shares the ARM64 table format
        (M_ARM, "arm", 8),
        (M_ARMNT, "arm", 8),
        (M_I386, "unsupported", 0),
        (M_IA64, "unsupported", 0),
        (0xDEAD, "unsupported", 0),
    ])
    def test_arch_classification(self, machine, arch, entry_size):
        pe = FakePE(machine=machine, exc=(DIR_RVA, 24),
                    mem={DIR_RVA: b"\x00" * 24})
        result = build_exception_structure(pe)
        assert result["machine"] == machine
        assert result["arch"] == arch
        assert result["entry_size"] == entry_size

    def test_missing_file_header_is_unsupported(self):
        pe = FakePE(exc=(DIR_RVA, 12), mem={DIR_RVA: rf(0x2000, 0x2050, 0)},
                    omit_file_header=True)
        result = build_exception_structure(pe)
        assert result["machine"] is None
        assert result["arch"] == "unsupported"

    def test_non_int_machine_is_unsupported(self):
        pe = FakePE(machine="nope", exc=(DIR_RVA, 12),
                    mem={DIR_RVA: rf(0x2000, 0x2050, 0)})
        result = build_exception_structure(pe)
        assert result["machine"] is None
        assert result["arch"] == "unsupported"

    def test_unsupported_machine_skips_the_walk(self):
        """
        A present directory on a non-table arch must report placement but
        decode no entries, so the validator emits one code rather than
        spurious per-entry noise.
        """
        pe = FakePE(machine=M_I386, exc=(DIR_RVA, 24),
                    mem={DIR_RVA: _control_table()})
        result = build_exception_structure(pe)
        assert result["functions"] == []
        assert result["truncations"] == []
        assert result["errors"] == []
        assert result["rva"] == DIR_RVA and result["size"] == 24


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_top_level_key_set_is_stable(self):
        expected = {"rva", "size", "machine", "arch", "entry_size",
                    "functions", "truncations", "errors"}
        pe = _amd64_pe(_control_table(), unwind=unwind_bytes())
        assert set(build_exception_structure(pe)) == expected

    def test_unsupported_path_has_same_key_set(self):
        """The early return must not produce a different shape."""
        expected = {"rva", "size", "machine", "arch", "entry_size",
                    "functions", "truncations", "errors"}
        pe = FakePE(machine=M_I386, exc=(DIR_RVA, 24),
                    mem={DIR_RVA: b"\x00" * 24})
        assert set(build_exception_structure(pe)) == expected

    def test_amd64_entry_key_set(self):
        expected = {"index", "begin_rva", "end_rva", "unwind_info_rva",
                    "unwind", "errors"}
        pe = _amd64_pe(rf(0x2000, 0x2050, UW_RVA), size=12,
                       unwind=unwind_bytes())
        assert set(build_exception_structure(pe)["functions"][0]) == expected

    def test_arm_entry_key_set(self):
        """ARM entries add is_packed / packed_data."""
        expected = {"index", "begin_rva", "end_rva", "unwind_info_rva",
                    "unwind", "is_packed", "packed_data", "errors"}
        pe = FakePE(machine=M_ARM64, exc=(DIR_RVA, 8),
                    mem={DIR_RVA: arm_rec(0x2000, 0x4000)})
        assert set(build_exception_structure(pe)["functions"][0]) == expected

    def test_unwind_key_set(self):
        expected = {"version", "flags", "size_of_prolog", "count_of_codes",
                    "is_chained", "chained_rva", "errors"}
        assert set(_first_unwind(unwind_bytes())) == expected

    def test_indices_are_sequential(self):
        entries = b"".join(rf(0x2000 + i * 0x100, 0x2050 + i * 0x100, 0)
                           for i in range(4))
        pe = _amd64_pe(entries, size=48)
        result = build_exception_structure(pe)
        assert [f["index"] for f in result["functions"]] == [0, 1, 2, 3]

    def test_json_serialisable(self):
        import json
        pe = _amd64_pe(_control_table(), unwind=unwind_bytes(flags=0x01))
        json.dumps(build_exception_structure(pe))   # must not raise

    def test_never_raises_on_hostile_input(self):
        """
        Random bytes at every surface must produce a struct, not an exception.
        """
        import os
        for seed in range(20):
            blob = os.urandom(64)
            pe = FakePE(machine=M_AMD64, exc=(DIR_RVA, 48),
                        mem={DIR_RVA: blob, UW_RVA: blob})
            result = build_exception_structure(pe)
            assert isinstance(result, dict)


# =================================================================
# Counted-array walk
# =================================================================

class TestFunctionTableWalk:

    def test_entry_count_derived_from_size_and_stride(self):
        pe = _amd64_pe(_control_table(), size=24)
        assert len(build_exception_structure(pe)["functions"]) == 2

    def test_size_smaller_than_data_limits_the_walk(self):
        """The declared Size is authoritative, not the available bytes."""
        pe = _amd64_pe(_control_table(), size=12)
        assert len(build_exception_structure(pe)["functions"]) == 1

    def test_arm_stride_is_eight(self):
        entries = arm_rec(0x2000, 0x4000) + arm_rec(0x2100, 0x4100)
        pe = FakePE(machine=M_ARM64, exc=(DIR_RVA, 16), mem={DIR_RVA: entries})
        assert len(build_exception_structure(pe)["functions"]) == 2

    def test_ragged_tail_tagged_and_partial_entry_not_decoded(self):
        pe = _amd64_pe(_control_table(), size=25)
        result = build_exception_structure(pe)
        assert result["truncations"] == ["exception_table_ragged_tail"]
        assert len(result["functions"]) == 2   # the partial 3rd is not decoded

    def test_unmapped_entry_tagged_read_failed(self):
        """Declaring more entries than are mapped raises inside get_data."""
        pe = _amd64_pe(_control_table(), size=36)
        result = build_exception_structure(pe)
        assert result["truncations"] == ["exception_entry_read_failed"]
        assert len(result["functions"]) == 2

    def test_short_read_tagged_entry_truncated(self):
        """A read running past the mapped blob returns short, not an error."""
        entries = rf(0x2000, 0x2050, 0) + b"\x00\x00\x00"
        pe = _amd64_pe(entries, size=24)
        result = build_exception_structure(pe)
        assert result["truncations"] == ["exception_entry_truncated"]
        assert len(result["functions"]) == 1

    def test_read_failed_and_truncated_are_distinct(self):
        """
        The two tags mean different things - unmapped vs short - and the
        validator surfaces both under EXCEPTION_TABLE_TRUNCATED. Pin that they
        do not collapse into one.
        """
        unmapped = build_exception_structure(
            _amd64_pe(_control_table(), size=36))["truncations"]
        short = build_exception_structure(
            _amd64_pe(rf(0x2000, 0x2050, 0) + b"\x00", size=24))["truncations"]
        assert unmapped == ["exception_entry_read_failed"]
        assert short == ["exception_entry_truncated"]

    def test_max_functions_clamp_tagged(self):
        """
        A bogus Size claiming more than 2**20 entries is clamped and tagged
        before the walk begins.
        """
        size = ((1 << 20) + 1) * 12
        pe = _amd64_pe(rf(0x2000, 0x2050, 0), size=size)
        result = build_exception_structure(pe)
        assert "exception_table_max_exceeded" in result["truncations"]

    def test_empty_walk_when_size_below_one_entry(self):
        pe = _amd64_pe(_control_table(), size=8)
        result = build_exception_structure(pe)
        assert result["functions"] == []
        assert result["truncations"] == ["exception_table_ragged_tail"]


# =================================================================
# AMD64 entry decode
# =================================================================

class TestAmd64EntryDecode:

    def test_fields_decoded_little_endian(self):
        pe = _amd64_pe(rf(0x11223344, 0x55667788, 0x99AABBCC), size=12)
        f = build_exception_structure(pe)["functions"][0]
        assert f["begin_rva"] == 0x11223344
        assert f["end_rva"] == 0x55667788
        assert f["unwind_info_rva"] == 0x99AABBCC

    def test_clean_entry_has_no_errors(self):
        pe = _amd64_pe(rf(0x2000, 0x2050, UW_RVA), size=12,
                       unwind=unwind_bytes())
        assert build_exception_structure(pe)["functions"][0]["errors"] == []

    @pytest.mark.parametrize("begin,end,unwind,tags", [
        (0, 0x2050, UW_RVA, ["begin_rva_zero"]),
        (0x2000, 0, UW_RVA, ["end_rva_zero"]),
        (0x2000, 0x2050, 0, ["unwind_rva_zero"]),
        (0, 0, 0, ["begin_rva_zero", "end_rva_zero", "unwind_rva_zero"]),
    ])
    def test_zero_field_tags(self, begin, end, unwind, tags):
        pe = _amd64_pe(rf(begin, end, unwind), size=12,
                       unwind=unwind_bytes())
        assert build_exception_structure(pe)["functions"][0]["errors"] == tags

    def test_zero_unwind_rva_skips_unwind_decode(self):
        """No pointer means no .xdata read; unwind stays None."""
        pe = _amd64_pe(rf(0x2000, 0x2050, 0), size=12)
        assert build_exception_structure(pe)["functions"][0]["unwind"] is None

    def test_nonzero_unwind_rva_triggers_decode(self):
        pe = _amd64_pe(rf(0x2000, 0x2050, UW_RVA), size=12,
                       unwind=unwind_bytes())
        assert build_exception_structure(pe)["functions"][0]["unwind"] is not None


# =================================================================
# UNWIND_INFO decode
# =================================================================

class TestUnwindInfoDecode:

    def test_header_fields_decoded(self):
        u = _first_unwind(unwind_bytes(version=1, flags=0x01, prolog=0x12,
                                       count=3))
        assert u["version"] == 1
        assert u["flags"] == 0x01
        assert u["size_of_prolog"] == 0x12
        assert u["count_of_codes"] == 3

    def test_byte0_bit_packing(self):
        """version occupies bits[2:0]; flags bits[7:3]."""
        u = _first_unwind(unwind_bytes(version=3, flags=0x0F))
        assert u["version"] == 3
        assert u["flags"] == 0x0F

    @pytest.mark.parametrize("version", [1, 2, 3])
    def test_valid_versions_untagged(self, version):
        assert _first_unwind(unwind_bytes(version=version))["errors"] == []

    @pytest.mark.parametrize("version", [0, 4, 5, 6, 7])
    def test_invalid_versions_tagged(self, version):
        u = _first_unwind(unwind_bytes(version=version))
        assert "unwind_version_invalid" in u["errors"]

    @pytest.mark.parametrize("flags", [0x00, 0x01, 0x02, 0x08, 0x0B])
    def test_known_flag_bits_untagged(self, flags):
        assert _first_unwind(unwind_bytes(flags=flags))["errors"] == []

    @pytest.mark.parametrize("flags", [0x10, 0x18, 0x1F])
    def test_reserved_flag_bits_tagged(self, flags):
        u = _first_unwind(unwind_bytes(flags=flags))
        assert "unwind_flags_reserved_bits" in u["errors"]

    def test_unmapped_unwind_rva_tagged_read_failed(self):
        pe = _amd64_pe(rf(0x2000, 0x2050, 0x9000), size=12)
        u = build_exception_structure(pe)["functions"][0]["unwind"]
        assert u["errors"] == ["unwind_read_failed"]
        assert u["version"] is None   # nothing decoded

    def test_short_header_tagged_truncated(self):
        pe = _amd64_pe(rf(0x2000, 0x2050, UW_RVA), size=12,
                       unwind=b"\x01\x04")   # 2 of 4 bytes
        u = build_exception_structure(pe)["functions"][0]["unwind"]
        assert u["errors"] == ["unwind_truncated"]

    def test_version_and_flags_tags_can_coexist(self):
        u = _first_unwind(unwind_bytes(version=5, flags=0x10))
        assert u["errors"] == ["unwind_version_invalid",
                               "unwind_flags_reserved_bits"]


# =================================================================
# Chained unwind
# =================================================================

class TestChainedUnwind:

    def test_chain_resolved_for_v1(self):
        u = _first_unwind(unwind_bytes(version=1, flags=0x04, count=0,
                                       chain=(0x2000, 0x2050, 0x4000)))
        assert u["is_chained"] is True
        assert u["chained_rva"] == 0x4000

    def test_chain_resolved_for_v2(self):
        u = _first_unwind(unwind_bytes(version=2, flags=0x04, count=0,
                                       chain=(0x2000, 0x2050, 0x4000)))
        assert u["is_chained"] is True
        assert u["chained_rva"] == 0x4000

    @pytest.mark.parametrize("count,expected_offset", [
        (0, 4), (1, 8), (2, 8), (3, 12), (4, 12),
    ])
    def test_chain_offset_skips_even_padded_code_array(self, count,
                                                       expected_offset):
        """
        Unwind codes are USHORT[] padded to an even count, so the trailing
        RUNTIME_FUNCTION sits at 4 + ((count+1) & ~1) * 2.
        """
        u = _first_unwind(unwind_bytes(version=1, flags=0x04, count=count,
                                       chain=(0, 0, 0x4444)))
        assert u["chained_rva"] == 0x4444
        assert 4 + (((count + 1) & ~1) * 2) == expected_offset

    def test_missing_trailing_record_tagged(self):
        """CHAININFO set but no trailing RUNTIME_FUNCTION present."""
        u = _first_unwind(unwind_bytes(version=1, flags=0x04, count=0))
        assert u["errors"] == ["unwind_codes_truncated"]
        assert u["is_chained"] is True
        assert u["chained_rva"] is None

    def test_short_trailing_record_tagged(self):
        blob = unwind_bytes(version=1, flags=0x04, count=0) + b"\x00" * 6
        u = _first_unwind(blob)
        assert u["errors"] == ["unwind_codes_truncated"]

    def test_v3_recognised_but_chain_not_resolved(self):
        """
        V3 (APX preview) repacks the payload, so the parser surfaces
        version/flags and declines to follow the chain rather than
        mis-decoding it.
        """
        u = _first_unwind(unwind_bytes(version=3, flags=0x04, count=0,
                                       chain=(0, 0, 0x4000)))
        assert u["version"] == 3
        assert u["flags"] == 0x04
        assert u["is_chained"] is False
        assert u["chained_rva"] is None
        assert u["errors"] == []      # recognised, not an error

    def test_no_chain_flag_means_no_resolution(self):
        u = _first_unwind(unwind_bytes(version=1, flags=0x01, count=0,
                                       chain=(0, 0, 0x4000)))
        assert u["is_chained"] is False
        assert u["chained_rva"] is None

    def test_chain_and_version_tags_coexist(self):
        """A reserved-bit flag alongside CHAININFO still resolves the chain."""
        u = _first_unwind(unwind_bytes(version=1, flags=0x04 | 0x10, count=0,
                                       chain=(0, 0, 0x4000)))
        assert "unwind_flags_reserved_bits" in u["errors"]
        assert u["chained_rva"] == 0x4000


# =================================================================
# ARM / ARM64 entry decode
# =================================================================

class TestArmEntryDecode:

    def _arm(self, begin: int, word1: int, machine: int = M_ARM64):
        pe = FakePE(machine=machine, exc=(DIR_RVA, 8),
                    mem={DIR_RVA: arm_rec(begin, word1)})
        return build_exception_structure(pe)["functions"][0]

    def test_flag_zero_yields_xdata_rva(self):
        f = self._arm(0x2000, 0x4000)
        assert f["is_packed"] is False
        assert f["unwind_info_rva"] == 0x4000
        assert f["packed_data"] is None

    @pytest.mark.parametrize("flag", [1, 2, 3])
    def test_nonzero_flag_yields_packed_data(self, flag):
        word1 = 0x0AB10000 | flag
        f = self._arm(0x2000, word1)
        assert f["is_packed"] is True
        assert f["unwind_info_rva"] is None   # no .xdata pointer to check
        assert f["packed_data"] == word1

    def test_xdata_rva_is_dword_aligned(self):
        """
        The .xdata pointer is taken as (word1 & ~3).

        Note the mask is NOT observable from the output: this branch is only
        reached when Flag == 0, which by definition means the low 2 bits are
        already clear, so masked and unmasked values are always identical.
        Removing the mask is therefore a behaviour-preserving change and this
        test cannot detect it - verified by mutation. The mask is defensive,
        and what IS observable is that the resulting RVA is DWORD-aligned.
        """
        assert self._arm(0x2000, 0x4000)["unwind_info_rva"] % 4 == 0
        assert self._arm(0x2000, 0x8004)["unwind_info_rva"] % 4 == 0

    def test_zero_xdata_rva_tagged(self):
        f = self._arm(0x2000, 0x0)
        assert f["errors"] == ["unwind_rva_zero"]

    def test_packed_entry_never_tags_unwind_rva_zero(self):
        """Packed records have no .xdata pointer, so the tag must not fire."""
        f = self._arm(0x2000, 0x00000001)
        assert f["errors"] == []
        assert f["unwind_info_rva"] is None

    def test_begin_zero_tagged(self):
        assert self._arm(0, 0x4000)["errors"] == ["begin_rva_zero"]

    def test_end_rva_always_none(self):
        """ARM(64) .pdata carries no EndAddress field."""
        assert self._arm(0x2000, 0x4000)["end_rva"] is None
        assert self._arm(0x2000, 0x1)["end_rva"] is None

    def test_unwind_always_none(self):
        """.xdata / packed bodies are out of scope for this parser."""
        assert self._arm(0x2000, 0x4000)["unwind"] is None

    @pytest.mark.parametrize("machine", [M_ARM64, M_ARM64EC, M_ARM, M_ARMNT])
    def test_all_arm_machines_decode_identically(self, machine):
        """
        ARM64EC and ARM32 use the same 8-byte record, so the decode must not
        vary by machine - only the arch label does.
        """
        f = self._arm(0x2000, 0x4000, machine=machine)
        assert f["begin_rva"] == 0x2000
        assert f["unwind_info_rva"] == 0x4000
        assert f["is_packed"] is False


# =================================================================
# Parser -> validator contract
# =================================================================

class TestValidatorContract:
    """
    The tombstone vocabulary is a contract with
    validators.exception_table, whose priority lists consume these exact
    strings. A tag renamed here without updating the validator would silently
    stop being reported.
    """

    ENTRY_TAGS = {"entry_truncated", "entry_read_failed", "entry_unpack_failed",
                  "begin_rva_zero", "end_rva_zero", "unwind_rva_zero"}
    UNWIND_TAGS = {"unwind_read_failed", "unwind_truncated",
                   "unwind_unpack_failed", "unwind_version_invalid",
                   "unwind_flags_reserved_bits", "unwind_codes_truncated"}
    TRUNCATION_TAGS = {"exception_table_ragged_tail",
                       "exception_table_max_exceeded",
                       "exception_entry_read_failed",
                       "exception_entry_truncated"}

    def test_entry_tags_are_in_the_agreed_vocabulary(self):
        pe = _amd64_pe(rf(0, 0, 0), size=12)
        tags = set(build_exception_structure(pe)["functions"][0]["errors"])
        assert tags <= self.ENTRY_TAGS

    def test_arm_entry_tags_are_in_the_agreed_vocabulary(self):
        pe = FakePE(machine=M_ARM64, exc=(DIR_RVA, 8),
                    mem={DIR_RVA: arm_rec(0, 0)})
        tags = set(build_exception_structure(pe)["functions"][0]["errors"])
        assert tags <= self.ENTRY_TAGS

    @pytest.mark.parametrize("blob,expected", [
        (b"\x01\x04", "unwind_truncated"),
        (unwind_bytes(version=5), "unwind_version_invalid"),
        (unwind_bytes(flags=0x10), "unwind_flags_reserved_bits"),
        (unwind_bytes(version=1, flags=0x04), "unwind_codes_truncated"),
    ])
    def test_unwind_tags_are_in_the_agreed_vocabulary(self, blob, expected):
        u = _first_unwind(blob)
        assert expected in u["errors"]
        assert set(u["errors"]) <= self.UNWIND_TAGS

    def test_unmapped_unwind_tag_in_vocabulary(self):
        pe = _amd64_pe(rf(0x2000, 0x2050, 0x9000), size=12)
        u = build_exception_structure(pe)["functions"][0]["unwind"]
        assert set(u["errors"]) <= self.UNWIND_TAGS

    @pytest.mark.parametrize("size,mem_key,expected", [
        (25, DIR_RVA, "exception_table_ragged_tail"),
        (36, DIR_RVA, "exception_entry_read_failed"),
    ])
    def test_truncation_tags_are_in_the_agreed_vocabulary(self, size, mem_key,
                                                          expected):
        pe = _amd64_pe(_control_table(), size=size)
        truncations = build_exception_structure(pe)["truncations"]
        assert expected in truncations
        assert set(truncations) <= self.TRUNCATION_TAGS

    def test_top_level_errors_stays_empty_on_recoverable_faults(self):
        """
        The parser records recoverable faults per-entry or per-table; the
        top-level `errors` list drives the validator's short-circuit and must
        not be populated by ordinary decode problems.
        """
        pe = _amd64_pe(rf(0, 0, 0) + b"\x00\x00", size=25)
        assert build_exception_structure(pe)["errors"] == []


# =================================================================
# Defensive unpack branches
# =================================================================

class TestDefensiveUnpackBranches:
    """
    Four `except struct.error` clauses that are UNREACHABLE through the public
    API. Each is preceded by an explicit length guard:

      _decode_amd64_entry  <- `if len(raw) < entry_size: break` in the walk
      _decode_arm_entry    <- same guard
      _decode_unwind_info  <- `if len(header) < _UNWIND_HEADER_SIZE: return`
      (chain unpack)       <- `if len(rf) < _RUNTIME_FUNCTION_SIZE: tag`

    Verified: a get_data returning a LONGER buffer than requested, or a
    bytearray, still unpacks cleanly, so no realistic pefile behaviour reaches
    them. They exist so a future refactor that weakens a guard degrades to a
    tombstone instead of raising - the parser's "never raises" contract.

    The two entry branches are reached by calling the private helper directly
    with a short buffer. The two unwind branches are reachable only by
    injecting a struct.error, since the guard and the unpack read the same
    buffer; mock.patch is used deliberately rather than contorting the input.
    """

    def test_amd64_entry_short_buffer_yields_tombstone(self):
        from iocx.parsers.pe_exception import _decode_amd64_entry
        entry = _decode_amd64_entry(None, b"\x00" * 11, index=7)
        assert entry["errors"] == ["entry_unpack_failed"]
        assert entry["index"] == 7
        assert entry["begin_rva"] is None
        assert entry["end_rva"] is None
        assert entry["unwind_info_rva"] is None
        assert entry["unwind"] is None

    def test_amd64_tombstone_key_set_matches_normal_entry(self):
        """
        The tombstone must be shape-compatible with a decoded entry, or the
        validator's .get() calls would silently see missing fields.
        """
        from iocx.parsers.pe_exception import _decode_amd64_entry
        tombstone = _decode_amd64_entry(None, b"\x00" * 11, index=0)
        pe = _amd64_pe(rf(0x2000, 0x2050, UW_RVA), size=12,
                       unwind=unwind_bytes())
        normal = build_exception_structure(pe)["functions"][0]
        assert set(tombstone) == set(normal)

    def test_arm_entry_short_buffer_yields_tombstone(self):
        from iocx.parsers.pe_exception import _decode_arm_entry
        entry = _decode_arm_entry(b"\x00" * 7, index=9, arch="arm64")
        assert entry["errors"] == ["entry_unpack_failed"]
        assert entry["index"] == 9
        assert entry["begin_rva"] is None
        assert entry["end_rva"] is None
        assert entry["unwind_info_rva"] is None
        assert entry["unwind"] is None
        assert entry["is_packed"] is None

    def test_arm_tombstone_key_set_matches_normal_entry(self):
        from iocx.parsers.pe_exception import _decode_arm_entry
        tombstone = _decode_arm_entry(b"\x00" * 7, index=0, arch="arm64")
        pe = FakePE(machine=M_ARM64, exc=(DIR_RVA, 8),
                    mem={DIR_RVA: arm_rec(0x2000, 0x4000)})
        normal = build_exception_structure(pe)["functions"][0]
        # the tombstone omits packed_data, which is only meaningful when a
        # Flag was actually decoded
        assert set(tombstone) | {"packed_data"} == set(normal)

    def test_unwind_header_unpack_failure_yields_tombstone(self):
        """
        Header unpack cannot fail past the length guard, so inject the error
        to prove the handler degrades rather than propagating.
        """
        import struct as _struct
        from unittest import mock
        from iocx.parsers.pe_exception import _decode_unwind_info

        real = _struct.unpack_from

        def fail_header(fmt, *args, **kwargs):
            if fmt == "<BBBB":
                raise _struct.error("injected")
            return real(fmt, *args, **kwargs)

        pe = FakePE(mem={UW_RVA: unwind_bytes()})
        with mock.patch("iocx.parsers.pe_exception.struct.unpack_from",
                        side_effect=fail_header):
            u = _decode_unwind_info(pe, UW_RVA)

        assert u["errors"] == ["unwind_unpack_failed"]
        assert u["version"] is None
        assert u["flags"] is None
        assert u["is_chained"] is False

    def test_chained_record_unpack_failure_is_tagged(self):
        """
        The trailing RUNTIME_FUNCTION unpack is guarded by a length check too.
        On injected failure the entry stays marked chained with an unresolved
        target, rather than raising.
        """
        import struct as _struct
        from unittest import mock
        from iocx.parsers.pe_exception import _decode_unwind_info

        real = _struct.unpack_from

        def fail_chain(fmt, *args, **kwargs):
            if fmt == "<III":
                raise _struct.error("injected")
            return real(fmt, *args, **kwargs)

        blob = unwind_bytes(version=1, flags=0x04, count=0,
                            chain=(0, 0, 0x4000))
        pe = FakePE(mem={UW_RVA: blob})
        with mock.patch("iocx.parsers.pe_exception.struct.unpack_from",
                        side_effect=fail_chain):
            u = _decode_unwind_info(pe, UW_RVA)

        assert "unwind_unpack_failed" in u["errors"]
        assert u["is_chained"] is True      # flag was read before the failure
        assert u["chained_rva"] is None     # but the target is unresolved

    def test_unpack_failed_tag_is_in_the_agreed_vocabulary(self):
        """entry_unpack_failed / unwind_unpack_failed are consumed by the
        validator's priority lists; pin them alongside the reachable tags."""
        from iocx.parsers.pe_exception import _decode_amd64_entry, _decode_arm_entry
        assert set(_decode_amd64_entry(None, b"\x00" * 11, 0)["errors"]) <= \
            TestValidatorContract.ENTRY_TAGS
        assert set(_decode_arm_entry(b"\x00" * 7, 0, "arm64")["errors"]) <= \
            TestValidatorContract.ENTRY_TAGS

    @pytest.mark.parametrize("length", [0, 1, 11])
    def test_amd64_never_raises_on_any_short_buffer(self, length):
        from iocx.parsers.pe_exception import _decode_amd64_entry
        entry = _decode_amd64_entry(None, b"\x00" * length, index=0)
        assert entry["errors"] == ["entry_unpack_failed"]

    @pytest.mark.parametrize("length", [0, 1, 7])
    def test_arm_never_raises_on_any_short_buffer(self, length):
        from iocx.parsers.pe_exception import _decode_arm_entry
        entry = _decode_arm_entry(b"\x00" * length, index=0, arch="arm64")
        assert entry["errors"] == ["entry_unpack_failed"]

    def test_guards_make_these_branches_unreachable_in_practice(self):
        """
        Documents WHY the branches are otherwise uncovered: the walk breaks on
        a short read before calling the decoder, so the decoder always sees a
        full-stride buffer.
        """
        entries = rf(0x2000, 0x2050, 0) + b"\x00\x00\x00"   # 3-byte tail
        result = build_exception_structure(_amd64_pe(entries, size=24))
        assert result["truncations"] == ["exception_entry_truncated"]
        # the partial entry never reached _decode_amd64_entry
        assert len(result["functions"]) == 1
        assert result["functions"][0]["errors"] == ["unwind_rva_zero"]


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_parses_are_identical(self):
        import json
        entries = (rf(0x2000, 0x2050, UW_RVA)
                   + rf(0, 0, 0)
                   + rf(0x2100, 0x2150, 0x9000))
        pe = _amd64_pe(entries, size=37, unwind=unwind_bytes(version=5,
                                                             flags=0x14))
        first = json.dumps(build_exception_structure(pe), sort_keys=True)
        for _ in range(20):
            assert json.dumps(build_exception_structure(pe),
                              sort_keys=True) == first

    def test_tag_order_is_stable(self):
        """Zero-field tags are appended in a fixed begin/end/unwind order."""
        pe = _amd64_pe(rf(0, 0, 0), size=12)
        for _ in range(20):
            assert build_exception_structure(pe)["functions"][0]["errors"] == [
                "begin_rva_zero", "end_rva_zero", "unwind_rva_zero"]
