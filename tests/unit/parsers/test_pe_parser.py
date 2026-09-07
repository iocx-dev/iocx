# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest, pefile, json
from types import SimpleNamespace
from typing import Dict, Any, Optional, List

from iocx.parsers.pe_parser import (parse_pe, _walk_resources, analyse_pe_sections, _parse_data_directories,
                                    _parse_data_directories_raw, _parse_resources, _MAX_RESOURCE_STRINGS,
                                    _MAX_RESOURCE_ENTRIES, _MAX_RESOURCE_DEPTH)
from iocx.parsers.string_extractor import extract_strings_from_bytes
from iocx.parsers.pe_resources import build_resource_structure


class _DataStruct:
    def __init__(self, offset, size, codepage=0):
        self.OffsetToData = offset
        self.Size = size
        self.CodePage = codepage


class _Data:
    def __init__(self, offset, size):
        self.struct = _DataStruct(offset, size)


class _Node:
    def __init__(self, entries):
        self.entries = entries


class _Entry:
    def __init__(self, **kw):
        self.name = None
        self.id = None
        for k, v in kw.items():
            setattr(self, k, v)


class _FakePE:
    def __init__(self, root, file_size=0x10000000):
        self.DIRECTORY_ENTRY_RESOURCE = root
        self.__data__ = type("D", (), {"size": file_size})()

    def get_data(self, rva, size):
        return b"A" * size

    def get_memory_mapped_image(self):
        return b"\x00" * 0x10000

    def get_offset_from_rva(self, rva):
        return rva



def _leaf(offset=0x100, size=0x40):
    e = _Entry(id=0x409)
    e.data = _Data(offset, size)
    return e


def _name_entry(langs, name_id=1):
    e = _Entry(id=name_id)
    e.directory = _Node(langs)
    return e


def _type_entry(names, type_id=16):
    e = _Entry(id=type_id)
    e.directory = _Node(names)
    return e


def _tree(name_entries, type_id=16):
    return _Node([_type_entry(name_entries, type_id)])


# ------------------------------------------------------------
# Fake PE builder with full interface required by parse_pe()
# ------------------------------------------------------------

@pytest.fixture
def fake_strings(monkeypatch):
    """
    Replace extract_strings_from_bytes with a fixed-rate fake: one
    fabricated string per 4 input bytes, regardless of content.

    Patches the name as bound INSIDE iocx.parsers.pe_parser's own
    namespace - `from .string_extractor import extract_strings_from_bytes`
    binds a local reference there, so patching the origin module
    (string_extractor) would not affect it.
    """
    import iocx.parsers.pe_parser as pe_parser_module

    def fake(data: bytes):
        return [f"S{i}" for i in range(len(data) // 4)]

    monkeypatch.setattr(pe_parser_module, "extract_strings_from_bytes", fake)
    return fake


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


class TestResourceStringsCap:

    # The cap is the unit under test, not the extractor. Make the fake
    # unconditional for the class so no test can silently fall back to
    # the real scanner.
    @pytest.fixture(autouse=True)
    def _always_fake(self, fake_strings):
        return fake_strings

    def test_many_small_resources_bounded(self):
        tree = _tree([_name_entry([_leaf(0x100, 4000)], name_id=i)
            for i in range(500)])
        _, strings, truncated = _parse_resources(_FakePE(tree))
        assert len(strings) == _MAX_RESOURCE_STRINGS
        assert "resource_strings" in truncated

    def test_single_large_resource_bounded(self):
        tree = _tree([_name_entry([_leaf(0x100, 400_000)])])
        _, strings, truncated = _parse_resources(_FakePE(tree))
        assert len(strings) == _MAX_RESOURCE_STRINGS
        assert "resource_strings" in truncated

    @pytest.mark.parametrize("blob_size", [4, 400, 40_000, 400_000])
    def test_never_exceeds_the_cap(self, blob_size):
        tree = _tree([_name_entry([_leaf(0x100, blob_size)], name_id=i)
                for i in range(200)])
        _, strings, _ = _parse_resources(_FakePE(tree))
        assert len(strings) <= _MAX_RESOURCE_STRINGS

    def test_under_cap_not_flagged(self):
        tree = _tree([_name_entry([_leaf(0x100, 0x40)])])
        _, strings, truncated = _parse_resources(_FakePE(tree))
        assert len(strings) < _MAX_RESOURCE_STRINGS
        assert "resource_strings" not in truncated

    def test_fake_pe_satisfies_the_parser_interface(self):
        """_parse_resources returns early and silently when
        get_memory_mapped_image is absent, so an incomplete fake yields
        empty resources rather than an error."""
        pe = _FakePE(_tree([_name_entry([_leaf(0x100, 0x40)])]))
        for attr in ("get_data", "get_memory_mapped_image", "get_offset_from_rva"):
            assert callable(getattr(pe, attr, None)), attr


class TestResourceEntriesCap:

    @pytest.mark.parametrize("count,expected_capped", [
        (_MAX_RESOURCE_ENTRIES - 1, False),
        (_MAX_RESOURCE_ENTRIES, False),
        (_MAX_RESOURCE_ENTRIES + 1, True),
    ])
    def test_entry_cap_boundary(self, count, expected_capped):
        """Small blobs keep the string budget clear so the entry cap is
        the only one under test."""
        tree = _tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                      for i in range(count)])
        resources, _, truncated = _parse_resources(_FakePE(tree))
        assert len(resources) == min(count, _MAX_RESOURCE_ENTRIES)
        assert ("resources" in truncated) is expected_capped

    def test_far_over_cap_bounded(self):
        tree = _tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                      for i in range(50_000)])
        resources, _, truncated = _parse_resources(_FakePE(tree))
        assert len(resources) == _MAX_RESOURCE_ENTRIES
        assert "resources" in truncated

    def test_output_size_does_not_scale_with_input(self):
        """The property that matters downstream."""
        def sized(n):
            tree = _tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                          for i in range(n)])
            return len(json.dumps(_parse_resources(_FakePE(tree))[0]))
        assert sized(2_000) == sized(50_000)
        assert sized(2_000) > 2

    def test_cap_flag_appears_once(self):
        tree = _tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                      for i in range(5_000)])
        _, _, truncated = _parse_resources(_FakePE(tree))
        assert truncated.count("resources") == 1

    def test_outer_loop_breaks_after_cap(self):
        """
        The cap fires inside the first type's name loop, which breaks the
        inner loop only. The outer `if entries_capped: break` is what stops
        the walk from advancing to the next type entry.

        Without it the second type is still blocked by the inner
        `len(resources) >= _MAX_RESOURCE_ENTRIES` check - but that check
        appends "resources" again, so the flag is duplicated.
        """
        over_cap = [_name_entry([_leaf(0x100, 4)], name_id=i)
                for i in range(_MAX_RESOURCE_ENTRIES + 1)]
        root = _Node([
        _type_entry(over_cap, type_id=16),
        _type_entry([_name_entry([_leaf(0x100, 4)], name_id=9000)],
        type_id=3),
        ])

        resources, _, truncated = _parse_resources(_FakePE(root))

        assert len(resources) == _MAX_RESOURCE_ENTRIES
        assert truncated == ["resources"]
        assert all(r["type"] != "RT_ICON" for r in resources)


class TestRecursionDepthCap:

    def test_deep_tree_does_not_raise(self):
        """
        Before the cap this raised RecursionError out of _parse_resources,
        which parse_pe does not catch - so one malformed file aborted the
        whole analysis.
        """
        node = _Node([_leaf()])
        for _ in range(2_000):
            e = _Entry(id=1)
            e.directory = node
            node = _Node([e])
        strings = []
        _walk_resources(_FakePE(node), node, strings)   # must not raise

    def test_normal_depth_unaffected(self):
        """A well-formed tree is Type -> Name -> Language, three levels."""
        tree = _tree([_name_entry([_leaf(0x100, 0x40)])])
        strings = []
        _walk_resources(_FakePE(tree), tree, strings)
        assert strings

    def test_depth_cap_is_generous_enough_for_real_trees(self):
        assert _MAX_RESOURCE_DEPTH >= 3


class TestCapsAreIndependent:

    def test_both_caps_can_fire_together(self, fake_strings):
        tree = _tree([_name_entry([_leaf(0x100, 4000)], name_id=i)
                      for i in range(5_000)])
        resources, strings, truncated = _parse_resources(_FakePE(tree))
        assert len(resources) == _MAX_RESOURCE_ENTRIES
        assert len(strings) == _MAX_RESOURCE_STRINGS
        assert set(truncated) == {"resources", "resource_strings"}

    def test_entry_cap_alone(self, fake_strings):
        tree = _tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                      for i in range(5_000)])
        _, _, truncated = _parse_resources(_FakePE(tree))
        assert truncated == ["resources"]


class TestUnaffectedBehaviour:

    def test_clean_file_has_no_truncation_flags(self):
        tree = _tree([_name_entry([_leaf(0x100, 0x40)])])
        resources, strings, truncated = _parse_resources(_FakePE(tree))
        assert truncated == []
        assert len(resources) == 1
        assert strings

    def test_no_resource_directory(self):
        pe = _FakePE(None)
        pe.DIRECTORY_ENTRY_RESOURCE = None
        assert _parse_resources(pe) == ([], [], [])

    def test_ordering_still_deterministic(self):
        def build():
            return _tree([_name_entry([_leaf(0x100, 64)], name_id=i)
                          for i in range(2_000)])
        first = json.dumps(_parse_resources(_FakePE(build()))[0], sort_keys=True)
        for _ in range(5):
            assert json.dumps(_parse_resources(_FakePE(build()))[0],
                              sort_keys=True) == first

    def test_caps_are_positive_and_bounded(self):
        assert 0 < _MAX_RESOURCE_STRINGS <= 1_000_000
        assert 0 < _MAX_RESOURCE_ENTRIES <= 65_536
        assert 0 < _MAX_RESOURCE_DEPTH <= 64


class TestResourcesUnavailable:

    def test_missing_method_is_tombstoned(self):
        """An empty `resources` list must be distinguishable from a
        binary that genuinely has none."""
        class _NoMMI(_FakePE):
            @property
            def get_memory_mapped_image(self):
                raise AttributeError("get_memory_mapped_image")

        pe = _NoMMI(_tree([_name_entry([_leaf(0x100, 0x40)])]))
        resources, strings, truncated = _parse_resources(pe)
        assert resources == []
        assert "resources_unavailable" in truncated
        assert strings # the walk still ran

    def test_raising_method_is_tombstoned_not_propagated(self):
        class _RaisingMMI(_FakePE):
            def get_memory_mapped_image(self):
                raise struct.error("truncated image")

        pe = _RaisingMMI(_tree([_name_entry([_leaf(0x100, 0x40)])]))
        resources, _, truncated = _parse_resources(pe)
        assert resources == []
        assert "resources_map_read_failed" in truncated

    def test_tombstone_and_cap_are_mutually_exclusive(self):
        pe = _FakePE(_tree([_name_entry([_leaf(0x100, 4)], name_id=i)
                for i in range(5_000)]))
        _, _, truncated = _parse_resources(pe)
        assert "resources" in truncated
        assert "resources_unavailable" not in truncated

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


@pytest.mark.parametrize("raw, label", [
    (None, "attribute absent"),
    (b"", "zero-length buffer"),
])
def test_parse_data_directories_raw_no_raw_bytes(raw, label):
    """
    `if not raw` catches an empty buffer as well as a missing attribute -
    the other parsers use `is None`, which would fall through to
    struct.unpack_from on b"" here. A zero-length file genuinely has no
    optional header, so both must return early.
    """
    class FakeOptHdr:
        Magic = 0x10B
        def get_file_offset(self):
            return 0xE8

    pe = SimpleNamespace(OPTIONAL_HEADER=FakeOptHdr())
    if raw is not None:
        pe.__data__ = raw

    from iocx.parsers.pe_parser import _parse_data_directories_raw
    assert _parse_data_directories_raw(pe) == [], label


@pytest.mark.parametrize("readable", [0, 1, 3, 15])
def test_parse_data_directories_raw_truncated_header(readable):
    """
    A short optional header must yield the entries that were readable,
    not an empty list and not an exception. `break` rather than `return
    dirs` is what makes the partial result survive.
    """
    import struct
    opt_offset, data_dir_offset = 0, 96

    class FakeOptHdr:
        Magic = 0x10B # PE32 -> 96-byte offset
        def get_file_offset(self):
            return opt_offset

    # Fill each readable slot with a recognisable (rva, size) pair, then
    # stop one byte short of completing the next.
    payload = b"".join(
        struct.pack("<II", 0x1000 + i, 0x40 + i) for i in range(readable)
    )
    raw = b"\x00" * data_dir_offset + payload + b"\x00" * 7

    pe = SimpleNamespace(OPTIONAL_HEADER=FakeOptHdr(), __data__=raw)

    from iocx.parsers.pe_parser import _parse_data_directories_raw
    dirs = _parse_data_directories_raw(pe)

    assert len(dirs) == readable
    assert [d["index"] for d in dirs] == list(range(readable))
    assert all(d["rva"] == 0x1000 + d["index"] for d in dirs)
    assert all(d["size"] == 0x40 + d["index"] for d in dirs)


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
