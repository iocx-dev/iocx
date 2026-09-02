# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_resources.

Strategy differs from the other parser suites: pe_resources consumes
pefile's already-parsed DIRECTORY_ENTRY_RESOURCE tree rather than raw
bytes, so the fixtures are duck-typed stand-ins for pefile's
ResourceDirData / ResourceDirEntryData objects rather than byte buffers.

Two malformation shapes drive most of these tests, because they are what
the parser's guards exist for:

  * a node whose `.entries` is missing or unreadable
  * an entry that is neither a directory nor a data leaf

Both previously propagated out of build_resource_structure, breaking the
never-raises contract every other parser in this package holds.

Note the string-table walk and the main tree walk disagree on one test:

    build_entry : getattr(e, "directory", None) is not None
    string walk : hasattr(name_entry, "directory")     <-- no None check

so an entry with `directory = None` AND a valid `.data` is a data leaf to
the first and a directory to the second. `_hybrid_entry` exploits that to
reach the string walk's exception handler without disturbing the main tree.
Narrowing the string walk to match would make that handler unreachable.
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

import pefile
import pytest

from iocx.parsers.pe_resources import build_resource_structure

_RT_STRING = 6
_RT_ICON = 3


# =================================================================
# pefile-shaped fixtures
# =================================================================

class _DataDir:
    def __init__(self, va: int):
        self.VirtualAddress = va


class _OptHdr:
    def __init__(self, va: int):
        # index 2 is IMAGE_DIRECTORY_ENTRY_RESOURCE
        self.DATA_DIRECTORY = [None, None, _DataDir(va)]


class _Struct:
    def __init__(self, offset_to_data: int, size: int = 0):
        self.OffsetToData = offset_to_data
        self.Size = size


class _Data:
    def __init__(self, offset: int, size: int):
        self.struct = _Struct(offset, size)


class _Node:
    """Stands in for pefile.ResourceDirData."""
    def __init__(self, entries):
        self.entries = entries


class _NoEntries:
    """A directory object lacking `.entries` - a malformed subtree."""


class _RaisingEntries:
    """A directory whose `.entries` access raises."""
    @property
    def entries(self):
        raise ValueError("corrupt entry list")


class _Entry:
    def __init__(self, **kw):
        self.name = None
        self.id = None
        for k, v in kw.items():
            setattr(self, k, v)


class _FakePE:
    def __init__(self, root, base_rva: int = 0x1000,
                 raise_on_offset: bool = False,
                 has_resource_dir: bool = True,
                 has_optional_header: bool = True):
        if has_resource_dir:
            self.DIRECTORY_ENTRY_RESOURCE = root
        if has_optional_header:
            self.OPTIONAL_HEADER = _OptHdr(base_rva)
        self._raise_on_offset = raise_on_offset

    def get_offset_from_rva(self, rva: int) -> int:
        if self._raise_on_offset:
            raise pefile.PEFormatError("unmapped rva")
        return rva - 0x1000 + 0x400


# ---- tree builders ----

def _data_entry(offset: int = 0x1100, size: int = 0x40,
                entry_id: Optional[int] = 0x409,
                name: Optional[str] = None) -> _Entry:
    e = _Entry(id=entry_id, name=name)
    e.data = _Data(offset, size)
    e.struct = _Struct(0)
    return e


def _dir_entry(children, offset: int = 0x10,
               entry_id: Optional[int] = 1,
               name: Optional[str] = None) -> _Entry:
    e = _Entry(id=entry_id, name=name)
    e.directory = _Node(children)
    e.struct = _Struct(0x80000000 | offset)
    return e


def _hybrid_entry() -> _Entry:
    """
    directory=None plus a valid .data. A data leaf to the main walk, a
    directory to the string walk - the only shape that reaches the string
    walk's exception handler while leaving the main tree intact.
    """
    e = _Entry(id=1)
    e.directory = None
    e.data = _Data(0x1100, 0x40)
    e.struct = _Struct(0)
    return e


def _string_tree(tables=((0x1100, 0x40),)) -> _Node:
    """A well-formed RT_STRING subtree: Type -> Name -> Language -> data."""
    langs = [_data_entry(off, size) for off, size in tables]
    return _Node([_dir_entry([_dir_entry(langs, offset=0x10)],
                             offset=0x20, entry_id=_RT_STRING)])


# =================================================================
# Absence
# =================================================================

class TestAbsence:

    def test_no_resource_directory_returns_none(self):
        pe = _FakePE(None, has_resource_dir=False)
        assert build_resource_structure(pe) is None

    def test_missing_optional_header_returns_none(self):
        """
        The data directory is needed for the base RVA; without it no RVA in
        the tree can be derived, so returning None beats emitting a tree of
        meaningless addresses.
        """
        pe = _FakePE(_Node([]), has_optional_header=False)
        assert build_resource_structure(pe) is None

    def test_empty_root_directory(self):
        out = build_resource_structure(_FakePE(_Node([])))
        assert out["root"]["entries"] == []
        assert out["root"]["size"] == 16      # header only
        assert out["root"]["errors"] == []
        assert out["string_tables"] == []
        assert out["errors"] == []


# =================================================================
# RVA derivation
# =================================================================

class TestRvaDerivation:

    def test_root_rva_is_the_directory_base(self):
        out = build_resource_structure(_FakePE(_Node([]), base_rva=0x5000))
        assert out["root"]["rva"] == 0x5000

    def test_subdirectory_rva_is_base_plus_offset(self):
        tree = _Node([_dir_entry([], offset=0x20)])
        out = build_resource_structure(_FakePE(tree, base_rva=0x5000))
        assert out["root"]["entries"][0]["directory"]["rva"] == 0x5020

    def test_high_bit_is_masked_off_the_offset(self):
        """
        OffsetToData carries 0x80000000 to mark "is directory"; leaving it in
        would place every subdirectory ~2GB past the image.
        """
        tree = _Node([_dir_entry([], offset=0x30)])
        out = build_resource_structure(_FakePE(tree, base_rva=0x1000))
        assert out["root"]["entries"][0]["directory"]["rva"] == 0x1030

    def test_nested_depth_derives_independently(self):
        """Each level's RVA comes from its own entry struct, not by
        accumulation, so a deep tree does not drift."""
        tree = _Node([_dir_entry([_dir_entry([], offset=0x10)], offset=0x20)])
        out = build_resource_structure(_FakePE(tree, base_rva=0x5000))
        type_dir = out["root"]["entries"][0]["directory"]
        name_dir = type_dir["entries"][0]["directory"]
        assert type_dir["rva"] == 0x5020
        assert name_dir["rva"] == 0x5010


# =================================================================
# Size derivation
# =================================================================

class TestSizeDerivation:

    @pytest.mark.parametrize("count,expected", [
        (0, 16), (1, 24), (2, 32), (5, 56),
    ])
    def test_size_is_header_plus_eight_per_entry(self, count, expected):
        tree = _Node([_data_entry() for _ in range(count)])
        out = build_resource_structure(_FakePE(tree))
        assert out["root"]["size"] == expected

    def test_size_uses_the_declared_count_not_the_decoded_count(self):
        """
        A skipped entry must not shrink the reported size: the directory
        header still claims that many entries, and the discrepancy between
        declared size and decoded entries is the signal.
        """
        tree = _Node([_data_entry(), _Entry(id=9)])   # second is undecodable
        out = build_resource_structure(_FakePE(tree))
        assert out["root"]["size"] == 32              # 16 + 8*2
        assert len(out["root"]["entries"]) == 1
        assert out["root"]["errors"] == ["entry_decode_failed"]


# =================================================================
# Entry decoding
# =================================================================

class TestEntryDecoding:

    def test_data_entry_fields(self):
        tree = _Node([_data_entry(offset=0x1234, size=0x56)])
        entry = build_resource_structure(_FakePE(tree))["root"]["entries"][0]
        assert entry["is_directory"] is False
        assert entry["directory"] is None
        assert entry["data_rva"] == 0x1234
        assert entry["data_size"] == 0x56
        assert entry["raw_offset"] == 0x1234 - 0x1000 + 0x400

    def test_directory_entry_fields(self):
        tree = _Node([_dir_entry([])])
        entry = build_resource_structure(_FakePE(tree))["root"]["entries"][0]
        assert entry["is_directory"] is True
        assert entry["directory"] is not None
        assert entry["data_rva"] is None
        assert entry["data_size"] is None
        assert entry["raw_offset"] is None

    def test_named_entry_records_the_name(self):
        tree = _Node([_data_entry(name="MYRESOURCE")])
        entry = build_resource_structure(_FakePE(tree))["root"]["entries"][0]
        assert entry["name"] == "MYRESOURCE"

    def test_unnamed_entry_records_none(self):
        tree = _Node([_data_entry(name=None)])
        assert build_resource_structure(
            _FakePE(tree))["root"]["entries"][0]["name"] is None

    def test_entry_id_recorded(self):
        tree = _Node([_data_entry(entry_id=0x0409)])
        assert build_resource_structure(
            _FakePE(tree))["root"]["entries"][0]["id"] == 0x0409

    def test_raw_offset_sentinel_on_unmapped_rva(self):
        """
        A corrupt data RVA yields -1 rather than aborting. The validator
        treats a negative raw offset as out-of-bounds, so the fact still
        reaches output.
        """
        tree = _Node([_data_entry()])
        out = build_resource_structure(_FakePE(tree, raise_on_offset=True))
        assert out["root"]["entries"][0]["raw_offset"] == -1


# =================================================================
# Per-entry guard - the never-raises contract
# =================================================================

class TestPerEntryGuard:
    """
    Before this guard, a malformed entry propagated out of the parser and
    took the whole analysis with it. Every other parser in the package holds
    a never-raises contract; these pin it here.
    """

    def test_entry_with_neither_data_nor_directory_is_skipped(self):
        tree = _Node([_Entry(id=9)])
        out = build_resource_structure(_FakePE(tree))
        assert out["root"]["entries"] == []
        assert out["root"]["errors"] == ["entry_decode_failed"]

    def test_sibling_entries_survive_a_bad_one(self):
        tree = _Node([_data_entry(0x1100), _Entry(id=9), _data_entry(0x1200)])
        out = build_resource_structure(_FakePE(tree))
        assert [e["data_rva"] for e in out["root"]["entries"]] == [0x1100, 0x1200]
        assert out["root"]["errors"] == ["entry_decode_failed"]

    def test_one_error_tag_per_failing_entry(self):
        tree = _Node([_Entry(id=1), _Entry(id=2), _data_entry()])
        out = build_resource_structure(_FakePE(tree))
        assert out["root"]["errors"] == ["entry_decode_failed"] * 2

    @pytest.mark.parametrize("broken", [_NoEntries, _RaisingEntries])
    def test_unreadable_subdirectory_is_contained(self, broken):
        """
        A subtree whose entry list cannot be read costs that subtree only;
        the parent still reports it as a directory entry.
        """
        e = _Entry(id=1)
        e.directory = broken()
        e.struct = _Struct(0x80000010)
        out = build_resource_structure(_FakePE(_Node([e])))
        subdir = out["root"]["entries"][0]["directory"]
        assert subdir["errors"] == ["directory_entries_unavailable"]
        assert subdir["entries"] == []
        assert subdir["size"] == 16     # header only; count unknowable
        assert out["root"]["errors"] == []

    def test_deep_failure_does_not_reach_the_root(self):
        bad = _Entry(id=1)
        bad.directory = _NoEntries()
        bad.struct = _Struct(0x80000010)
        tree = _Node([_dir_entry([_dir_entry([bad], offset=0x20)], offset=0x30)])
        out = build_resource_structure(_FakePE(tree))
        assert out["root"]["errors"] == []
        level1 = out["root"]["entries"][0]["directory"]
        level2 = level1["entries"][0]["directory"]
        level3 = level2["entries"][0]["directory"]
        assert level3["errors"] == ["directory_entries_unavailable"]

    def test_errors_key_present_on_every_directory(self):
        tree = _Node([_dir_entry([_dir_entry([_data_entry()])])])
        out = build_resource_structure(_FakePE(tree))

        def _walk(node):
            assert "errors" in node
            assert isinstance(node["errors"], list)
            for e in node["entries"]:
                if e["directory"] is not None:
                    _walk(e["directory"])

        _walk(out["root"])


# =================================================================
# RT_STRING walk
# =================================================================

class TestStringTableWalk:

    def test_healthy_walk_collects_tables(self):
        out = build_resource_structure(_FakePE(_string_tree()))
        assert out["string_tables"] == [{"rva": 0x1100, "size": 0x40}]
        assert out["errors"] == []

    def test_multiple_tables_collected_in_order(self):
        tree = _string_tree(((0x1100, 0x40), (0x1200, 0x80)))
        out = build_resource_structure(_FakePE(tree))
        assert out["string_tables"] == [{"rva": 0x1100, "size": 0x40},
                                        {"rva": 0x1200, "size": 0x80}]

    def test_walk_failure_is_tagged(self):
        """
        The line that was `except Exception: pass`. Without the tag, an empty
        list means both "no string resources" and "the walk broke".
        """
        tree = _Node([_dir_entry([_hybrid_entry()], offset=0x20,
                                 entry_id=_RT_STRING)])
        out = build_resource_structure(_FakePE(tree))
        assert out["errors"] == ["string_table_walk_failed"]
        assert out["string_tables"] == []

    def test_partial_collection_is_preserved(self):
        """
        Tables gathered before the raise are kept, so the tag means "may be
        incomplete" rather than "empty" - a non-empty list is not proof the
        walk finished.
        """
        good = _dir_entry([_data_entry(0x1100, 0x40)], offset=0x10)
        tree = _Node([_dir_entry([good, _hybrid_entry()], offset=0x20,
                                 entry_id=_RT_STRING)])
        out = build_resource_structure(_FakePE(tree))
        assert out["string_tables"] == [{"rva": 0x1100, "size": 0x40}]
        assert out["errors"] == ["string_table_walk_failed"]

    def test_no_rt_string_resources_is_not_an_error(self):
        """
        The distinction the tag exists for: an icon-only binary has an empty
        list and a CLEAN errors list.
        """
        tree = _Node([_dir_entry([_dir_entry([_data_entry()])],
                                 offset=0x20, entry_id=_RT_ICON)])
        out = build_resource_structure(_FakePE(tree))
        assert out["string_tables"] == []
        assert out["errors"] == []

    def test_walk_failure_does_not_break_the_main_tree(self):
        tree = _Node([_dir_entry([_hybrid_entry()], offset=0x20,
                                 entry_id=_RT_STRING)])
        out = build_resource_structure(_FakePE(tree))
        assert out["errors"] == ["string_table_walk_failed"]
        assert len(out["root"]["entries"]) == 1
        assert out["root"]["errors"] == []


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_top_level_keys(self):
        out = build_resource_structure(_FakePE(_string_tree()))
        assert set(out) == {"root", "string_tables", "errors"}

    def test_directory_node_keys(self):
        out = build_resource_structure(_FakePE(_Node([_data_entry()])))
        assert set(out["root"]) == {"rva", "size", "entries", "errors"}

    def test_entry_keys(self):
        out = build_resource_structure(_FakePE(_Node([_data_entry()])))
        assert set(out["root"]["entries"][0]) == {
            "name", "id", "is_directory", "directory",
            "data_rva", "data_size", "raw_offset"}

    def test_json_serialisable(self):
        import json
        json.dumps(build_resource_structure(_FakePE(_string_tree())))


# =================================================================
# Robustness
# =================================================================

class TestNeverRaises:

    def _random_entry(self, rng, depth=0):
        e = _Entry(id=rng.choice([None, 1, _RT_STRING, 0x409]))
        r = rng.random()
        if r < 0.20:
            return e                                    # neither branch
        if r < 0.40:
            e.data = _Data(rng.randint(0, 0xFFFF), rng.randint(0, 0xFF))
            e.struct = _Struct(0)
            return e
        if r < 0.50:
            e.directory = None                          # hybrid
            e.data = _Data(1, 1)
            e.struct = _Struct(0)
            return e
        if r < 0.60:
            e.directory = rng.choice([_NoEntries(), _RaisingEntries()])
            e.struct = _Struct(0x80000010)
            return e
        if depth > 2:
            e.data = _Data(1, 1)
            e.struct = _Struct(0)
            return e
        e.directory = _Node([self._random_entry(rng, depth + 1)
                             for _ in range(rng.randint(0, 3))])
        e.struct = _Struct(0x80000000 | rng.randint(0, 0xFFFF))
        return e

    def test_random_trees_never_raise(self):
        rng = random.Random(11)
        for _ in range(500):
            tree = _Node([self._random_entry(rng)
                          for _ in range(rng.randint(0, 4))])
            out = build_resource_structure(_FakePE(tree))
            assert isinstance(out, dict)

    def test_deeply_nested_tree(self):
        node = _Node([_data_entry()])
        for _ in range(50):
            e = _Entry(id=1)
            e.directory = node
            e.struct = _Struct(0x80000010)
            node = _Node([e])
        assert build_resource_structure(_FakePE(node)) is not None


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def _tree(self):
        return _Node([
            _dir_entry([_dir_entry([_data_entry(0x1100, 0x40)], offset=0x10)],
                       offset=0x20, entry_id=_RT_STRING),
            _Entry(id=9),                                   # undecodable
            _dir_entry([_data_entry(0x1200, 0x80)], offset=0x30),
        ])

    def test_repeated_parse_identical(self):
        import json
        first = json.dumps(build_resource_structure(_FakePE(self._tree())),
                           sort_keys=True)
        for _ in range(20):
            assert json.dumps(build_resource_structure(_FakePE(self._tree())),
                              sort_keys=True) == first

    def test_error_tag_order_is_stable(self):
        tree = _Node([_Entry(id=1), _data_entry(), _Entry(id=2)])
        for _ in range(10):
            out = build_resource_structure(_FakePE(tree))
            assert out["root"]["errors"] == ["entry_decode_failed"] * 2
