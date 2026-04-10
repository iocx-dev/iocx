import pytest
from types import SimpleNamespace

from iocx.parsers.pe_parser import parse_pe, _walk_resources, analyse_pe_sections
from iocx.parsers.string_extractor import extract_strings_from_bytes


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
    assert metadata["sections"] == [".text", ".rdata"]
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
    import pefile
    # Override the autouse patch for this test only
    def raise_peformaterror(path, fast_load=True):
        raise pefile.PEFormatError("bad file")

    monkeypatch.setattr(pefile, "PE", raise_peformaterror)

    result = parse_pe("not_a_real_pe.exe")

    assert result == {}

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
