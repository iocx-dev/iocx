# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest, pefile
from types import SimpleNamespace
from typing import Dict, Any, Optional, List

from iocx.parsers.pe_parser import parse_pe, _walk_resources, analyse_pe_sections, _parse_data_directories, _parse_data_directories_raw
from iocx.parsers.string_extractor import extract_strings_from_bytes
from iocx.parsers.pe_resources import build_resource_structure


# ------------------------------------------------------------
# Fake PE builder with full interface required by parse_pe()
# ------------------------------------------------------------

def fake_pe(
    imports=None,
    sections=None,
    resources=None,
    get_data=None,
):
    """Build a fake PE-like object with all required attributes."""

    # Fake __data__ with a .size attribute
    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    pe = SimpleNamespace()
    pe.__data__ = FakeData(b"\x00" * 1000)

    # Fake parse_data_directories()
    pe.parse_data_directories = lambda: None

    # Fake imports (must be bytes, not str)
    if imports is not None:
        class FakeImport:
            def __init__(self, dll):
                self.dll = dll # must be bytes

        pe.DIRECTORY_ENTRY_IMPORT = [FakeImport(i) for i in imports]

    # Fake sections
    class FakeSection:
        def __init__(self, name):
            # Name is an 8-byte, null-padded field in real PE sections
            self.Name = name.encode() + b"\x00" * (8 - len(name))
            # Minimal attributes used by parse_pe
            self.SizeOfRawData = 0
            self.Misc_VirtualSize = 0
            self.Characteristics = 0

        def get_data(self):
            return b""

        def get_entropy(self):
            return 0.0

    pe.sections = [FakeSection(s) for s in (sections or [])]

    # Fake resources
    if resources is not None:
        pe.DIRECTORY_ENTRY_RESOURCE = resources

    # Fake get_data
    if get_data is not None:
        pe.get_data = get_data
    else:
        pe.get_data = lambda rva, size: b""

    return pe


# ------------------------------------------------------------
# Monkeypatch pefile.PE so parse_pe() never loads a real file
# ------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_pefile(monkeypatch):
    def fake_loader(path, fast_load=True):
        raise RuntimeError("pefile.PE() should not be called in unit tests")

    import pefile
    monkeypatch.setattr(pefile, "PE", fake_loader)
    yield


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _walk(node: Dict[str, Any], acc: Optional[List] = None) -> List[Dict[str, Any]]:
    """Every directory node in the tree, root first."""
    acc = acc if acc is not None else []
    acc.append(node)
    for e in node["entries"]:
        if e["directory"] is not None:
            _walk(e["directory"], acc)
    return acc


def _data_leaves(root: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [e for d in _walk(root) for e in d["entries"] if not e["is_directory"]]


def _all_directory_errors(root: Dict[str, Any]) -> List:
    return [tag for d in _walk(root) for tag in d["errors"]]


# ------------------------------------------------------------
# Tests for parse_pe() using pure mocks
# ------------------------------------------------------------

def test_parse_pe_no_imports(monkeypatch):
    pe = fake_pe(imports=None, sections=[".text"])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert metadata["imports"] == []


def test_parse_pe_with_imports(monkeypatch):
    pe = fake_pe(imports=[b"kernel32.dll", b"ws2_32.dll"], sections=[".text"])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert "kernel32.dll" in metadata["imports"]
    assert "ws2_32.dll" in metadata["imports"]


def test_parse_pe_sections(monkeypatch):
    pe = fake_pe(imports=None, sections=[".text", ".rdata"])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")

    # Sections are now detailed dicts; assert on names only
    section_names = metadata["sections"]
    assert section_names == [".text", ".rdata"]

    # parse_pe no longer returns a separate section_analysis key
    assert "section_analysis" not in metadata


def test_parse_pe_no_resources(monkeypatch):
    pe = fake_pe(imports=None, sections=[".text"], resources=None)
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert metadata["resource_strings"] == []


def test_parse_pe_simple_resource(monkeypatch):
    class FakeDataStruct:
        OffsetToData = 0
        Size = 20

    class FakeData:
        struct = FakeDataStruct()

    class FakeEntry:
        data = FakeData()

    class FakeDir:
        entries = [FakeEntry()]

    pe = fake_pe(
        imports=None,
        sections=[".text"],
        resources=FakeDir(),
        get_data=lambda rva, size: b"Hello\x00World",
    )
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert "Hello" in metadata["resource_strings"]


def test_parse_pe_bad_resource(monkeypatch):
    class FakeDataStruct:
        OffsetToData = 0
        Size = 20

    class FakeData:
        struct = FakeDataStruct()

    class FakeEntry:
        data = FakeData()

    class FakeDir:
        entries = [FakeEntry()]

    pe = fake_pe(
        imports=None,
        sections=[".text"],
        resources=FakeDir(),
        get_data=lambda *a, **k: (_ for _ in ()).throw(Exception("bad RVA")),
    )
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert metadata["resource_strings"] == []


def test_parse_pe_large_resource(monkeypatch):
    class FakeDataStruct:
        OffsetToData = 0
        Size = 99999999 # too large

    class FakeData:
        struct = FakeDataStruct()

    class FakeEntry:
        data = FakeData()

    class FakeDir:
        entries = [FakeEntry()]

    pe = fake_pe(imports=None, sections=[".text"], resources=FakeDir())
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    pe_obj, metadata = parse_pe("dummy.exe")
    assert metadata["resource_strings"] == []


def test_parse_pe_handles_peformaterror(monkeypatch):
    # Override the autouse patch for this test only
    def raise_peformaterror(path, fast_load=True):
        raise pefile.PEFormatError("bad file")

    monkeypatch.setattr(pefile, "PE", raise_peformaterror)

    result = parse_pe("not_a_real_pe.exe")

    assert result == (None, {})

# ------------------------------------------------------------
# Direct tests for _walk_resources()
# ------------------------------------------------------------

def test_walk_resources_cycle():
    class FakeDir:
        def __init__(self):
            self.entries = []

    a = FakeDir()
    b = FakeDir()
    a.entries = [b]
    b.entries = [a] # cycle

    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    pe = SimpleNamespace(__data__=FakeData(b"\x00" * 1000))
    strings = []
    _walk_resources(pe, a, strings)
    assert strings == []


def test_walk_resources_directory_branch(monkeypatch):
    # Fake directory structure: root → child (no cycle)
    class ChildDir:
        entries = [] # no further entries

    class EntryWithDirectory:
        directory = ChildDir()

    class RootDir:
        entries = [EntryWithDirectory()]

    # Fake __data__ with .size attribute
    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    pe = SimpleNamespace(
        __data__=FakeData(b"\x00" * 1000),
        get_data=lambda *a, **k: b"" # won't be used
    )

    strings = []
    _walk_resources(pe, RootDir(), strings)

    # No strings expected, but the directory branch was executed
    assert strings == []


def test_walk_resources_recursion_guard():
    # Create two directory objects
    class Dir:
        def __init__(self):
            self.entries = []

    A = Dir()
    B = Dir()

    # Entry objects with .directory attributes
    class Entry:
        def __init__(self, directory):
            self.directory = directory

    # Create a cycle: A → B → A
    A.entries = [Entry(B)]
    B.entries = [Entry(A)]

    # Fake __data__ with .size attribute
    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    pe = SimpleNamespace(
        __data__=FakeData(b"\x00" * 1000),
        get_data=lambda *a, **k: b""
    )

    strings = []
    _walk_resources(pe, A, strings)

    # No strings expected, but recursion guard was hit
    assert strings == []


# ------------------------------------------------------------
# Analyse PE sections
# ------------------------------------------------------------

class FakeSection:
    def __init__(self):
        self.Name = b".text\x00\x00\x00"
        self.SizeOfRawData = 100
        self.Misc_VirtualSize = 80
        self.Characteristics = 0x60000020
        self._data = b"\x00" * 50

    def get_data(self):
        return self._data


class FakePE:
    def __init__(self):
        self.sections = [FakeSection()]


def test_analyse_pe_sections_basic():
    pe = FakePE()

    results = analyse_pe_sections(pe)

    assert len(results) == 1
    sec = results[0]

    # Name should be decoded and stripped of nulls
    assert sec["name"] == ".text"

    # Raw + virtual sizes
    assert sec["raw_size"] == 100
    assert sec["virtual_size"] == 80

    # Characteristics preserved
    assert sec["characteristics"] == 0x60000020

    # Entropy should be a float
    assert isinstance(sec["entropy"], float)


def test_parse_data_directories_no_optional_header():
    class FakePE:
        pass # no OPTIONAL_HEADER attribute at all

    result = _parse_data_directories(FakePE())

    assert result == [] # early return path


def test_parse_data_directories_raw_no_optional_header():
    class FakePE:
        pass # no OPTIONAL_HEADER attribute at all

    result = _parse_data_directories_raw(FakePE())
    assert result == [] # early return path


def test_analysis_sections_retain_placement_fields():
    """
    sanitize_sections strips raw_address and virtual_address for CLI
    output. The analysis layer needs both - rva_graph, sections and
    resources all key off them - so sanitisation must never be applied
    on that path.
    """
    pe = FakePE()
    sections = analyse_pe_sections(pe)
    assert sections
    for sec in sections:
        assert "raw_address" in sec
        assert "virtual_address" in sec


# =================================================================
# Defensive: guarded get_offset_from_rva
# =================================================================

class TestGuardedRvaToOffset:
    """
    Cover the try/except around pe.get_offset_from_rva in
    build_resource_structure. A corrupt RVA must produce a -1 sentinel
    in raw_offset rather than propagating the exception.
    """

    def _make_pe_with_data_leaf_raising(self, exception_to_raise: Exception):
        """
        Build a minimal fake pe whose resource tree contains a single
        RT_VERSION leaf, where pe.get_offset_from_rva raises the given
        exception.
        """

        def _struct_with(offset: int):
            return type("S", (), {"OffsetToData": offset})()

        # Leaf data entry — points to the corrupt RVA
        class _FakeStruct:
            OffsetToData = 0x1100
            Size = 100

        class _FakeData:
            struct = _FakeStruct()

        class _FakeLangEntry:
            id = 0x0409
            data = _FakeData()
            # No `directory` attribute — this is a leaf, not a subdirectory

        class _FakeLangDir:
            entries = [_FakeLangEntry()]

        # Name entry — points to the language directory
        class _FakeNameEntry:
            id = 1
            directory = _FakeLangDir()
            struct = _struct_with(0x80000020)  # high bit set = "is directory"

        class _FakeNameDir:
            entries = [_FakeNameEntry()]

        # Type entry — points to the name directory
        class _FakeTypeEntry:
            id = 16  # RT_VERSION
            directory = _FakeNameDir()
            struct = _struct_with(0x80000010)

        class _FakeRootDir:
            entries = [_FakeTypeEntry()]

        class _FakeDataDir:
            VirtualAddress = 0x1000

        class _FakeOptHdr:
            DATA_DIRECTORY = [None, None, _FakeDataDir()]

        class _FakePE:
            OPTIONAL_HEADER = _FakeOptHdr()
            DIRECTORY_ENTRY_RESOURCE = _FakeRootDir()

            def get_offset_from_rva(self, rva):
                raise exception_to_raise

        return _FakePE()

    def test_pefile_format_error_yields_minus_one(self):
        import pefile
        from iocx.parsers.pe_resources import build_resource_structure

        pe = self._make_pe_with_data_leaf_raising(
            pefile.PEFormatError("simulated corrupt RVA")
        )
        result = build_resource_structure(pe)

        assert result is not None
        # Walk down to the leaf data entry
        root = result["root"]
        type_dir = root["entries"][0]["directory"]
        name_dir = type_dir["entries"][0]["directory"]
        leaf = name_dir["entries"][0]

        assert leaf["is_directory"] is False
        assert leaf["raw_offset"] == -1
        # The other fields should still be populated normally
        assert leaf["data_rva"] == 0x1100
        assert leaf["data_size"] == 100

    def test_attribute_error_yields_minus_one(self):
        from iocx.parsers.pe_resources import build_resource_structure

        pe = self._make_pe_with_data_leaf_raising(
            AttributeError("simulated missing attribute")
        )
        result = build_resource_structure(pe)

        root = result["root"]
        type_dir = root["entries"][0]["directory"]
        name_dir = type_dir["entries"][0]["directory"]
        leaf = name_dir["entries"][0]

        assert leaf["raw_offset"] == -1
        assert leaf["data_rva"] == 0x1100
        assert leaf["data_size"] == 100

    @pytest.mark.parametrize("exc", [
        pefile.PEFormatError("unmapped rva"),
        AttributeError("no such attribute"),
    ])
    def test_caught_types_yield_sentinel_and_keep_the_entry(self, exc):
        """
        Assertions walk the tree rather than indexing root["entries"]the helper nests the leaf under Type -> Name -> Language, so the
        root's first entry is a directory, not the data leaf.
        """
        pe = self._make_pe_with_data_leaf_raising(exc)
        out = build_resource_structure(pe)
        leaves = _data_leaves(out["root"])
        assert len(leaves) == 1
        assert leaves[0]["raw_offset"] == -1
        assert _all_directory_errors(out["root"]) == []

    def test_uncaught_type_falls_through_to_the_per_entry_guard(self):
        """
        The inner except is narrow: a RuntimeError is NOT handled there, so
        it reaches the per-entry guard and the leaf is dropped from its
        containing directory.

        Widening the inner except to `Exception` would keep the leaf with
        raw_offset = -1 instead. Before the never-raises patch this was
        asserted as propagation; the per-entry guard now catches everything,
        so the observable difference moved from "does it raise" to "is the
        entry kept".
        """
        pe = self._make_pe_with_data_leaf_raising(RuntimeError("not caught"))
        out = build_resource_structure(pe)
        assert _data_leaves(out["root"]) == []
        assert _all_directory_errors(out["root"]) == ["entry_decode_failed"]

    def test_declared_size_survives_the_drop(self):
        """
        The containing directory still reports the size its header implies,
        so the gap between `size` and len(entries) remains interpretable.
        """
        pe = self._make_pe_with_data_leaf_raising(RuntimeError("not caught"))
        out = build_resource_structure(pe)
        dropped = [d for d in _walk(out["root"]) if d["errors"]][0]
        assert dropped["size"] == 24
        assert dropped["entries"] == []
