# Building PE Fixtures for Integration Tests

This document explains how to rebuild the PE fixtures used by the integration
test suite. All fixture source code is committed to the repository under:

```
examples/generators/c/
```

This directory contains the C and RC files used to generate the PE binaries
stored in:

```
tests/integration/fixtures/bin/
```

Each binary has a corresponding manifest in:

```
tests/integration/fixtures/manifests/
```

The fixtures embed known IOCs in specific PE sections and encodings so the
integration tests can validate the full binary‑extraction pipeline:

- PE parsing
- section traversal
- overlay extraction
- resource directory parsing
- ASCII and UTF‑16LE string extraction
- IOC extraction across all extractors
- normalisation and aggregation

These fixtures simulate realistic malware‑style binaries in a controlled,
repeatable way.

---

## Directory Layout

```
examples/
└── generators/
    └── c/
        ├── pe_basic.c
        ├── pe_overlay.c
        ├── pe_rsrc.c
        ├── pe_rsrc.rc
        └── pe_utf16.c

tests/
└── integration/
    └── fixtures/
        ├── bin/
        │   ├── pe_basic.exe
        │   ├── pe_overlay.exe
        │   ├── pe_rsrc.exe
        │   └── pe_utf16.exe
        └── manifests/
            ├── pe_basic.json
            ├── pe_overlay.json
            ├── pe_rsrc.json
            └── pe_utf16.json
```

---

## Requirements

To rebuild the fixtures, you need:

- **MinGW‑w64** (recommended)
- A Linux/macOS system with MinGW cross‑compiler installed
  or a Windows system with MinGW installed
- `make` (optional but convenient)

Example installation on Ubuntu:

```bash
sudo apt install mingw-w64
```

---

## Building All Fixtures

If a `Makefile` exists in `examples/generators/c/`, run:

```bash
cd examples/generators/c/
make
```

This will compile all `.c` and `.rc` files and output the binaries into:

```
tests/integration/fixtures/bin/
```

---

## Building Fixtures Manually

### 1. `pe_basic.exe`
ASCII IOCs embedded in `.data`.

```bash
x86_64-w64-mingw32-gcc examples/generators/c/pe_basic.c -o tests/integration/fixtures/bin/pe_basic.exe

```

---

### 2. `pe_overlay.exe`
IOC strings appended as overlay data.

```bash
x86_64-w64-mingw32-gcc examples/generators/c/pe_overlay.c -o tests/integration/fixtures/bin/pe_overlay.exe

echo "http://overlay.net/c2" >> pe_overlay.exe
echo "8.8.8.8" >> pe_overlay.exe

```

---

### 3. `pe_rsrc.exe`
IOC strings embedded in `.rsrc` string tables.

Compile the resource file:

```bash
x86_64-w64-mingw32-windres examples/generators/c/pe_rsrc.rc -O coff -o examples/generators/c/pe_rsrc.o

```

Compile and link:

```bash
x86_64-w64-mingw32-gcc examples/generators/c/pe_rsrc.c examples/generators/c/pe_rsrc.o -o tests/integration/fixtures/bin/pe_rsrc.exe

```

---

### 4. `pe_utf16.exe`
UTF‑16LE encoded strings in `.data`.

```bash
x86_64-w64-mingw32-gcc examples/generators/c/pe_utf16.c -o tests/integration/fixtures/bin/pe_utf16.exe

```

---

## Updating Manifests

Each fixture has a corresponding JSON manifest in:

```
tests/integration/fixtures/manifests/
```

When modifying or rebuilding a fixture:

1. Extract strings manually using tools like `strings`, or `pefile`.
2. Verify the IOCs appear exactly as expected.
3. Update the manifest accordingly.

Manifests must remain deterministic so integration tests stay stable.

---

## Adding New Fixtures

To add a new PE fixture:

1. Create a new C or RC file under `examples/generators/c/`.
2. Embed the IOCs you want to test.
3. Compile it into `tests/integration/fixtures/bin/`.
4. Create a manifest in `tests/integration/fixtures/manifests/`.
5. Add the fixture name to the parameter list in `test_pe_fixtures.py`.

Guidelines:

- Keep binaries between 50 KB and 150 KB.
- Avoid randomness; fixtures must be deterministic.
- Prefer ASCII or UTF‑16LE strings.
- Use MinGW for consistent output across platforms.

---

## Philosophy

These fixtures provide realistic, reproducible binaries that allow the
integration test suite to validate:

- binary parsing correctness
- string extraction robustness
- IOC extraction accuracy
- end‑to‑end CLI behaviour

They complement the unit tests by ensuring the entire pipeline works on real
executables, not just synthetic text.
