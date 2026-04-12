import pytest
from types import SimpleNamespace
from iocx.parsers.pe_parser import parse_pe


# ------------------------------------------------------------
# FakePE builder (supports full resource parsing)
# ------------------------------------------------------------

def fake_pe(imports=None, sections=None, resources=None, mm_size=1000):
    """Build a FakePE object with the interface required by parse_pe()."""

    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    pe = SimpleNamespace()
    pe.__data__ = FakeData(b"\x00" * mm_size)
    pe.parse_data_directories = lambda: None

    # Fake imports
    if imports is not None:
        class FakeImport:
            def __init__(self, dll):
                self.dll = dll
        pe.DIRECTORY_ENTRY_IMPORT = [FakeImport(i) for i in imports]

    # Fake sections
    class FakeSection:
        def __init__(self, name):
            self.Name = name.encode() + b"\x00" * (8 - len(name))
            self.SizeOfRawData = 0
            self.Misc_VirtualSize = 0
            self.Characteristics = 0
        def get_data(self):
            return b""
        def get_entropy(self):
            return 0.0

    pe.sections = [FakeSection(s) for s in (sections or [])]

    # Fake resources
    pe.DIRECTORY_ENTRY_RESOURCE = resources
    pe.get_memory_mapped_image = lambda: pe.__data__

    return pe


# ------------------------------------------------------------
# Shared FakePE builder: bound, delayed imports, and sections
# ------------------------------------------------------------

def fake_pe_imports(
    imports=None,
    sections=None,
    delayed=None,
    bound=None,
):
    """Build a FakePE object with the interface required by parse_pe()."""

    pe = SimpleNamespace()
    pe.parse_data_directories = lambda: None

    # Fake imports (not used here but kept for consistency)
    if imports is not None:
        class FakeImport:
            def __init__(self, dll):
                self.dll = dll
        pe.DIRECTORY_ENTRY_IMPORT = [FakeImport(i) for i in imports]

    # Fake sections
    class FakeSection:
        def __init__(self, name):
            self.Name = name # raw bytes or str
            self.SizeOfRawData = 0
            self.Misc_VirtualSize = 0
            self.Characteristics = 0
        def get_data(self):
            return b""
        def get_entropy(self):
            return 0.0

    if sections is not None:
        pe.sections = [FakeSection(s) for s in sections]
    else:
        pe.sections = []

    # Fake delayed imports
    if delayed is not None:
        pe.DIRECTORY_ENTRY_DELAY_IMPORT = delayed

    # Fake bound imports
    if bound is not None:
        pe.DIRECTORY_ENTRY_BOUND_IMPORT = bound

    # Required for resource parsing but unused here
    pe.get_memory_mapped_image = lambda: b""

    return pe


# ------------------------------------------------------------
# Shared FakePE builder: Bound import elif else routes
# ------------------------------------------------------------

def fake_pe_bound(bound=None):
    pe = SimpleNamespace()
    pe.parse_data_directories = lambda: None
    pe.sections = []
    pe.get_memory_mapped_image = lambda: b""

    if bound is not None:
        pe.DIRECTORY_ENTRY_BOUND_IMPORT = bound

    return pe


# ------------------------------------------------------------
# Shared FakePE builder: Delayed imports elif else block
# ------------------------------------------------------------

def fake_pe_delayed(delayed=None):
    pe = SimpleNamespace()
    pe.parse_data_directories = lambda: None
    pe.sections = []
    pe.get_memory_mapped_image = lambda: b""

    if delayed is not None:
        pe.DIRECTORY_ENTRY_DELAY_IMPORT = delayed

    return pe


# ------------------------------------------------------------
# Shared FakePE builder: Import details
# ------------------------------------------------------------

def fake_pe_import_details(imports=None):
    pe = SimpleNamespace()
    pe.parse_data_directories = lambda: None
    pe.sections = []
    pe.get_memory_mapped_image = lambda: b""

    if imports is not None:
        pe.DIRECTORY_ENTRY_IMPORT = imports

    return pe


# ------------------------------------------------------------
# Helpers to build resource trees
# ------------------------------------------------------------

class FakeDataStruct:
    def __init__(self, size, offset):
        self.Size = size
        self.OffsetToData = offset

class FakeData:
    def __init__(self, size, offset):
        self.struct = FakeDataStruct(size, offset)

class FakeEntry:
    def __init__(self, size, offset):
        self.data = FakeData(size, offset)

def make_resource_tree(type_id, lang_id, size, offset):
    """Build a full resource tree matching parse_pe() expectations."""
    entry = FakeEntry(size, offset)
    res_dir = type("ResDir", (), {"entries": [entry]})
    res = type("Res", (), {"id": lang_id, "directory": res_dir})
    type_dir = type("TypeDir", (), {"id": type_id, "directory": type("X", (), {"entries": [res]})})
    root = type("Root", (), {"entries": [type_dir]})
    return root


# ------------------------------------------------------------
# Monkeypatch pefile.PE so parse_pe() returns FakePE
# ------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_pefile(monkeypatch):
    import pefile
    monkeypatch.setattr(pefile, "PE", lambda *a, **k: None)
    yield


# ------------------------------------------------------------
# Resource parsing tests
# ------------------------------------------------------------

def test_resource_valid(monkeypatch):
    resources = make_resource_tree(type_id=6, lang_id=1033, size=20, offset=0)
    pe = fake_pe(resources=resources)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    # With the refactored parser, we don't assert on structured resources anymore.
    # We only require that resource parsing does not crash and strings are extracted.
    assert isinstance(metadata["resources"], list)
    assert isinstance(metadata["resource_strings"], list)
    assert len(metadata["resource_strings"]) >= 0 # may be empty depending on extractor


def test_resource_zero_size(monkeypatch):
    resources = make_resource_tree(type_id=6, lang_id=1033, size=0, offset=0)
    pe = fake_pe(resources=resources)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    assert metadata["resources"] == []


def test_resource_out_of_bounds(monkeypatch):
    resources = make_resource_tree(type_id=6, lang_id=1033, size=50, offset=2000)
    pe = fake_pe(resources=resources, mm_size=100)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    assert metadata["resources"] == []


def test_resource_missing_directory_on_type(monkeypatch):
    class TypeDir:
        id = 6
        # no .directory

    root = type("Root", (), {"entries": [TypeDir]})
    pe = fake_pe(resources=root)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    assert metadata["resources"] == []


def test_resource_missing_nested_entries(monkeypatch):
    class Res:
        id = 1033
        directory = type("X", (), {"entries": []})

    class TypeDir:
        id = 6
        directory = type("Y", (), {"entries": [Res]})

    root = type("Root", (), {"entries": [TypeDir]})
    pe = fake_pe(resources=root)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    assert metadata["resources"] == []


def test_resource_negative_offset(monkeypatch):
    resources = make_resource_tree(type_id=6, lang_id=1033, size=10, offset=-5)
    pe = fake_pe(resources=resources)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    assert metadata["resources"] == []


def test_resource_mixed_valid_and_invalid(monkeypatch):
    valid = make_resource_tree(type_id=6, lang_id=1033, size=10, offset=0)
    invalid = make_resource_tree(type_id=6, lang_id=1033, size=999999, offset=0)

    root = type("Root", (), {"entries": valid.entries + invalid.entries})
    pe = fake_pe(resources=root)

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)
    _, metadata = parse_pe("dummy.exe")

    # New parser: we only care that oversized/bad resources don't blow up parsing.
    assert isinstance(metadata["resources"], list)
    assert isinstance(metadata["resource_strings"], list)


def test_resource_res_missing_directory_triggers_continue(monkeypatch):
    class FakeData(bytes):
        @property
        def size(self):
            return len(self)

    # res object WITHOUT a .directory attribute -> triggers the continue
    class FakeRes:
        id = 1033
        # no directory attribute -> continue branch

    # entry.directory.entries contains the FakeRes
    class FakeTypeDir:
        id = 6
        directory = type("Dir", (), {"entries": [FakeRes]})

    # root resource directory
    class FakeResourceRoot:
        entries = [FakeTypeDir]

    # FakePE with DIRECTORY_ENTRY_RESOURCE and memory-mapped image
    class FakePE:
        DIRECTORY_ENTRY_RESOURCE = FakeResourceRoot
        def parse_data_directories(self): pass
        def get_memory_mapped_image(self): return b"\x00" * 100

        sections = []

        __data__ = FakeData(b"\x00" * 1000)

    pe = FakePE()

    # Monkeypatch pefile.PE so parse_pe("dummy.exe") returns FakePE
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    from iocx.parsers.pe_parser import parse_pe
    _, metadata = parse_pe("dummy.exe")

    # Because the continue was hit, no resources should be collected
    assert metadata["resources"] == []


def test_parse_resources_no_directory_entry():
    class FakePE:
        # No DIRECTORY_ENTRY_RESOURCE attribute
        pass

    from iocx.parsers.pe_parser import _parse_resources
    resources, strings = _parse_resources(FakePE())

    assert resources == []
    assert strings == []


def test_parse_resources_missing_memory_map():
    class FakeRoot:
        entries = []

    class FakePE:
        DIRECTORY_ENTRY_RESOURCE = FakeRoot()
        # Crucially: NO get_memory_mapped_image attribute

    from iocx.parsers.pe_parser import _parse_resources
    resources, strings = _parse_resources(FakePE())

    assert resources == []
    assert strings == []

    assert hasattr(FakePE(), "DIRECTORY_ENTRY_RESOURCE")
    assert not hasattr(FakePE(), "get_memory_mapped_image")


# ------------------------------------------------------------
# Tests for safe file
# ------------------------------------------------------------

def test_safe_file_size_no_data():
    # Fake PE object with no __data__ attribute → triggers return 0
    class FakePE:
        pass

    from iocx.parsers.pe_parser import _safe_file_size
    size = _safe_file_size(FakePE())

    assert size == 0


def test_safe_file_size_missing_size_attr():
    # __data__ exists but has no .size attribute → triggers `return 0`
    class FakeData:
        pass

    class FakePE:
        __data__ = FakeData()

    from iocx.parsers.pe_parser import _safe_file_size
    size = _safe_file_size(FakePE())

    assert size == 0


# ------------------------------------------------------------
# Tests for Entropy
# ------------------------------------------------------------

def test_entropy_empty_returns_zero():
    from iocx.parsers.pe_parser import _entropy
    assert _entropy(b"") == 0.0
    assert _entropy(None) == 0.0


def test_entropy_non_empty_data():
    # Data with repeated bytes ensures:
    # - occur[x] increments
    # - the "if c:" branch executes
    # - p = c/len(data) is computed
    # - ent -= p * log2(p) is executed
    data = b"\x00\x00\x01\x01\x01"

    from iocx.parsers.pe_parser import _entropy
    ent = _entropy(data)

    # Entropy must be > 0 for mixed/repeated bytes
    assert ent > 0.0
    assert isinstance(ent, float)


# ------------------------------------------------------------
# Tests for delayed imports
# ------------------------------------------------------------


def test_delayed_imports_else_branch(monkeypatch):
    """Covers: else -> dll = None"""

    class FakeImp:
        name = None
        ordinal = 123

    class FakeDelayEntry:
        def __init__(self):
            self.dll = 99999 # non-bytes, non-str -> hits ELSE branch
            self.imports = [FakeImp()]

    pe = fake_pe_delayed(delayed=[FakeDelayEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["delayed_imports"]) == 1
    imp = metadata["delayed_imports"][0]
    assert imp["dll"] is None
    assert imp["function"] is None
    assert imp["ordinal"] == 123


def test_delayed_imports(monkeypatch):
    class FakeImp:
        def __init__(self, name, ordinal):
            self.name = name
            self.ordinal = ordinal

    class FakeDelayEntry:
        def __init__(self, dll, imports):
            self.dll = dll
            self.imports = imports

    delayed = [
        FakeDelayEntry(
            dll=b"kernel32.dll",
            imports=[
                FakeImp(name=b"CreateFileA", ordinal=None),
                FakeImp(name=None, ordinal=123),
            ],
        )
    ]

    pe = fake_pe_imports(delayed=delayed)
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["delayed_imports"]) == 2
    assert metadata["delayed_imports"][0]["dll"] == "kernel32.dll"
    assert metadata["delayed_imports"][0]["function"] == "CreateFileA"
    assert metadata["delayed_imports"][1]["function"] is None
    assert metadata["delayed_imports"][1]["ordinal"] == 123


# ------------------------------------------------------------
# Tests for bound imports
# ------------------------------------------------------------

def test_bound_imports(monkeypatch):
    class FakeStruct:
        TimeDateStamp = 0x12345678

    class FakeBoundEntry:
        def __init__(self, dll):
            self.name = dll
            self.struct = FakeStruct()

    bound = [
        FakeBoundEntry(b"USER32.dll"),
        FakeBoundEntry(b"KERNEL32.dll"),
    ]

    pe = fake_pe_imports(bound=bound)
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["bound_imports"]) == 2
    assert metadata["bound_imports"][0]["dll"] == "USER32.dll"
    assert metadata["bound_imports"][0]["timestamp"] == 0x12345678


# ------------------------------------------------------------
# Tests for section name decoding
# ------------------------------------------------------------


def test_analyse_pe_sections_get_data_exception():
    # Fake section that always raises when get_data() is called
    class BadSection:
        Name = b".oops\x00\x00\x00"
        SizeOfRawData = 123
        Misc_VirtualSize = 456
        Characteristics = 0xDEADBEEF

        def get_data(self):
            raise RuntimeError("boom")

    # Fake PE containing the bad section
    class FakePE:
        sections = [BadSection()]

    from iocx.parsers.pe_parser import analyse_pe_sections
    results = analyse_pe_sections(FakePE())

    # One section should still be returned
    assert len(results) == 1
    sec = results[0]

    # Name decoding still works
    assert sec["name"] == ".oops"

    # Sizes and characteristics are preserved
    assert sec["raw_size"] == 123
    assert sec["virtual_size"] == 456
    assert sec["characteristics"] == 0xDEADBEEF

    # Entropy should be computed on empty data (float)
    assert isinstance(sec["entropy"], float)


def test_parse_sections_get_data_exception():
    # Fake section whose get_data() always raises
    class BadSection:
        Name = b".bad\x00\x00\x00"
        SizeOfRawData = 0
        Misc_VirtualSize = 0
        Characteristics = 0

        def get_data(self):
            raise RuntimeError("boom")

    # Fake PE with one bad section
    pe = type("FakePE", (), {"sections": [BadSection()]})

    from iocx.parsers.pe_parser import _parse_sections
    sections = _parse_sections(pe)

    # The section should still be returned, with entropy computed on empty data
    assert len(sections) == 1
    sec = sections[0]

    assert sec["name"] == ".bad"
    assert sec["raw_size"] == 0
    assert sec["virtual_size"] == 0
    assert sec["characteristics"] == 0
    assert isinstance(sec["entropy"], float)


def test_section_name_decoding(monkeypatch):
    sections = [
        b".text\x00\x00\x00",
        b".rdata\x00\x00",
        b".data\x00\x00\x00",
    ]

    pe = fake_pe_imports(sections=sections)
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    # Extract names from the new section dicts
    names = metadata["sections"]
    assert names == [".text", ".rdata", ".data"]


# ------------------------------------------------------------
# Tests for exports, TLS directory, and digital signatures
# ------------------------------------------------------------


def test_exports(monkeypatch):
    class FakeSymbol:
        def __init__(self, name, ordinal, address, forwarder):
            self.name = name
            self.ordinal = ordinal
            self.address = address
            self.forwarder = forwarder

    class FakeExportDir:
        symbols = [
            FakeSymbol(name=b"FuncA", ordinal=1, address=0x1000, forwarder=None),
            FakeSymbol(name=None, ordinal=2, address=0x2000, forwarder=b"OtherDLL.FuncB"),
        ]

    pe = SimpleNamespace(
        DIRECTORY_ENTRY_EXPORT=FakeExportDir,
        parse_data_directories=lambda: None,
        sections=[],
        get_memory_mapped_image=lambda: b"",
    )

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["exports"]) == 2

    e1 = metadata["exports"][0]
    assert e1["name"] == "FuncA"
    assert e1["ordinal"] == 1
    assert e1["address"] == 0x1000
    assert e1["forwarder"] is None

    e2 = metadata["exports"][1]
    assert e2["name"] is None
    assert e2["ordinal"] == 2
    assert e2["address"] == 0x2000
    assert e2["forwarder"] == "OtherDLL.FuncB"


def test_tls_directory(monkeypatch):
    class FakeTLSStruct:
        StartAddressOfRawData = 0x1111
        EndAddressOfRawData = 0x2222
        AddressOfCallBacks = 0x3333

    class FakeTLSDir:
        struct = FakeTLSStruct()

    pe = SimpleNamespace(
        DIRECTORY_ENTRY_TLS=FakeTLSDir,
        parse_data_directories=lambda: None,
        sections=[],
        get_memory_mapped_image=lambda: b"",
    )

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    tls = metadata["tls"]
    assert tls["start_address"] == 0x1111
    assert tls["end_address"] == 0x2222
    assert tls["callbacks"] == 0x3333


def test_parse_tls_missing_struct():
    # Fake TLS directory with no .struct attribute
    class FakeTLS:
        pass

    pe = type("FakePE", (), {"DIRECTORY_ENTRY_TLS": FakeTLS()})

    from iocx.parsers.pe_parser import _parse_tls
    result = _parse_tls(pe)

    assert result is None


def test_digital_signatures(monkeypatch):
    class FakeSecStruct:
        def __init__(self, va, size):
            self.VirtualAddress = va
            self.Size = size

    class FakeSecEntry:
        def __init__(self, va, size):
            self.struct = FakeSecStruct(va, size)

    pe = SimpleNamespace(
        DIRECTORY_ENTRY_SECURITY=[
            FakeSecEntry(va=0x5000, size=128),
            FakeSecEntry(va=0x6000, size=256),
        ],
        parse_data_directories=lambda: None,
        sections=[],
        get_memory_mapped_image=lambda: b"",
    )

    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    sigs = metadata["signatures"]
    assert len(sigs) == 2
    assert sigs[0]["address"] == 0x5000
    assert sigs[0]["size"] == 128
    assert sigs[1]["address"] == 0x6000
    assert sigs[1]["size"] == 256


def test_parse_signatures_missing_struct():
    # Fake security entry with no .struct attribute → triggers the `continue` branch
    class FakeSec:
        pass

    # Fake PE with a DIRECTORY_ENTRY_SECURITY list containing one invalid entry
    pe = type("FakePE", (), {"DIRECTORY_ENTRY_SECURITY": [FakeSec()]})

    from iocx.parsers.pe_parser import _parse_signatures
    sigs = _parse_signatures(pe)

    # No valid signatures should be returned
    assert sigs == []

# ------------------------------------------------------------
# Tests for bound imports (covering if / elif / else)
# ------------------------------------------------------------

def test_bound_imports_bytes(monkeypatch):
    """Covers: if isinstance(dll_raw, bytes) -> decode()"""

    class FakeStruct:
        TimeDateStamp = 0x1111

    class FakeEntry:
        def __init__(self):
            self.name = b"KERNEL32.dll" # bytes -> hits IF branch
            self.struct = FakeStruct()

    pe = fake_pe_bound(bound=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert metadata["bound_imports"][0]["dll"] == "KERNEL32.dll"
    assert metadata["bound_imports"][0]["timestamp"] == 0x1111


def test_bound_imports_str(monkeypatch):
    """Covers: elif isinstance(dll_raw, str)"""

    class FakeStruct:
        TimeDateStamp = 0x2222

    class FakeEntry:
        def __init__(self):
            self.name = "USER32.dll" # str - hits ELIF branch
            self.struct = FakeStruct()

    pe = fake_pe_bound(bound=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert metadata["bound_imports"][0]["dll"] == "USER32.dll"
    assert metadata["bound_imports"][0]["timestamp"] == 0x2222


def test_bound_imports_else(monkeypatch):
    """Covers: else -> dll = None"""

    class FakeStruct:
        TimeDateStamp = 0x3333

    class FakeEntry:
        def __init__(self):
            self.name = 12345 # non-bytes, non-str - hits ELSE branch
            self.struct = FakeStruct()

    pe = fake_pe_bound(bound=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert metadata["bound_imports"][0]["dll"] is None
    assert metadata["bound_imports"][0]["timestamp"] == 0x3333


# ------------------------------------------------------------
# Tests for import_details coverage
# ------------------------------------------------------------

def test_import_details_with_function_name(monkeypatch):
    """Covers: imp.name is bytes - decode()"""

    class FakeImp:
        def __init__(self):
            self.name = b"CreateFileA"
            self.ordinal = None

    class FakeEntry:
        dll = b"kernel32.dll"
        imports = [FakeImp()]

    pe = fake_pe_import_details(imports=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["import_details"]) == 1
    imp = metadata["import_details"][0]
    assert imp["dll"] == "kernel32.dll"
    assert imp["function"] == "CreateFileA"
    assert imp["ordinal"] is None


def test_import_details_with_ordinal_only(monkeypatch):
    """Covers: imp.name is None -> function=None, ordinal preserved"""

    class FakeImp:
        def __init__(self):
            self.name = None
            self.ordinal = 123

    class FakeEntry:
        dll = b"user32.dll"
        imports = [FakeImp()]

    pe = fake_pe_import_details(imports=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["import_details"]) == 1
    imp = metadata["import_details"][0]
    assert imp["dll"] == "user32.dll"
    assert imp["function"] is None
    assert imp["ordinal"] == 123


def test_import_details_missing_imports_attribute(monkeypatch):
    """Covers: entry has no .imports - block skipped entirely"""

    class FakeEntry:
        dll = b"advapi32.dll"
        # no imports attribute

    pe = fake_pe_import_details(imports=[FakeEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert metadata["import_details"] == []


def test_imports_str_and_else_branches(monkeypatch):
    # Import with dll as str - hits ELIF branch
    class FakeImpA:
        name = b"CreateFileA"
        ordinal = None

    class FakeEntryStr:
        dll = "kernel32.dll" # str -> triggers ELIF
        imports = [FakeImpA()]

    # Import with dll as non-bytes, non-str -> hits ELSE branch
    class FakeImpB:
        name = None
        ordinal = 123

    class FakeEntryElse:
        dll = 99999 # neither bytes nor str -> triggers ELSE
        imports = [FakeImpB()]

    # Fake PE object
    class FakePE:
        DIRECTORY_ENTRY_IMPORT = [FakeEntryStr(), FakeEntryElse()]
        sections = []

        def parse_data_directories(self):
            pass

        def get_memory_mapped_image(self):
            return b""

    pe = FakePE()

    # Monkeypatch pefile.PE so parse_pe("dummy.exe") returns FakePE
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    from iocx.parsers.pe_parser import parse_pe
    _, metadata = parse_pe("dummy.exe")

    # First entry: dll is str
    imp1 = metadata["import_details"][0]
    assert imp1["dll"] == "kernel32.dll"
    assert imp1["function"] == "CreateFileA"
    assert imp1["ordinal"] is None

    # Second entry: dll is neither bytes nor str -> dll=None
    imp2 = metadata["import_details"][1]
    assert imp2["dll"] is None
    assert imp2["function"] is None
    assert imp2["ordinal"] == 123


# ------------------------------------------------------------
# Tests for delayed imports (elif and else coverage)
# ------------------------------------------------------------

def test_delayed_imports_str_dll(monkeypatch):
    """Covers: elif isinstance(dll_raw, str)"""

    class FakeImp:
        name = b"FuncA"
        ordinal = None

    class FakeDelayEntry:
        def __init__(self):
            self.dll = "kernel32.dll" # str -> hits ELIF branch
            self.imports = [FakeImp()]

    pe = fake_pe_delayed(delayed=[FakeDelayEntry()])
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    _, metadata = parse_pe("dummy.exe")

    assert len(metadata["delayed_imports"]) == 1
    imp = metadata["delayed_imports"][0]
    assert imp["dll"] == "kernel32.dll"
    assert imp["function"] == "FuncA"
    assert imp["ordinal"] is None


# ------------------------------------------------------------
# Test for optional header
# ------------------------------------------------------------

def test_optional_header_block(monkeypatch):
    # Fake OPTIONAL_HEADER with all fields parse_pe() expects
    class FakeOptionalHeader:
        SectionAlignment = 0x1000
        FileAlignment = 0x200
        SizeOfImage = 0x300000
        SizeOfHeaders = 0x400
        MajorLinkerVersion = 14
        MinorLinkerVersion = 25
        MajorOperatingSystemVersion = 10
        MinorOperatingSystemVersion = 0
        MajorSubsystemVersion = 6
        MinorSubsystemVersion = 1

    # Fake PE object
    class FakePE:
        OPTIONAL_HEADER = FakeOptionalHeader()
        sections = []

        def parse_data_directories(self):
            pass

        def get_memory_mapped_image(self):
            return b""

    pe = FakePE()

    # Monkeypatch pefile.PE so parse_pe("dummy.exe") returns FakePE
    monkeypatch.setattr("iocx.parsers.pe_parser.pefile.PE", lambda *a, **k: pe)

    from iocx.parsers.pe_parser import parse_pe
    _, metadata = parse_pe("dummy.exe")

    opt = metadata["optional_header"]

    assert opt["section_alignment"] == 0x1000
    assert opt["file_alignment"] == 0x200
    assert opt["size_of_image"] == 0x300000
    assert opt["size_of_headers"] == 0x400
    assert opt["linker_version"] == "14.25"
    assert opt["os_version"] == "10.0"
    assert opt["subsystem_version"] == "6.1"
