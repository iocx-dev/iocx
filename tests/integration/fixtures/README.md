# Binary Fixtures for Integration Testing

This directory contains binary fixtures used by the integration test suite to
validate IOC extraction from real executable files. These fixtures are compiled
PE binaries (built with MinGW) that embed known IOCs in specific sections or
encodings. Each fixture has a corresponding JSON manifest describing the IOCs
expected to be extracted.

The goal of these fixtures is to test the full binary‑extraction pipeline:

- PE parsing
- Section traversal
- Overlay extraction
- Resource directory parsing
- ASCII and UTF‑16LE string extraction
- IOC extraction across all extractors
- Normalisation and aggregation
- CLI output consistency

These tests ensure that IOCX behaves correctly on realistic malware‑style
binaries, not just text files.

---

## Directory Structure

```
fixtures/
│
├── bin/          # Compiled PE binaries
│   ├── pe_basic.exe
│   ├── pe_overlay.exe
│   ├── pe_rsrc.exe
│   └── pe_utf16.exe
│
└── manifests/    # JSON manifests describing expected IOCs
    ├── pe_basic.json
    ├── pe_overlay.json
    ├── pe_rsrc.json
    └── pe_utf16.json
```

Each manifest contains:

```json
{
    "fixture": "pe_basic",
    "expected_iocs": [
        "http://example.com/c2",
        "192.168.44.10",
        "abcd1234deadbeef"
    ],
    "encoding": "ascii",
    "location": "data-section"
}
```

- **fixture** — name of the binary in `bin/`
- **expected_iocs** — IOCs that must be extracted from the binary
- **encoding** — how the strings are encoded inside the PE (`ascii` or `utf16-le`)
- **location** — where inside the PE the IOCs are embedded (data section, overlay, resource table, etc.)

---

## Fixture Overview

### **pe_basic.exe**
- ASCII strings embedded in `.data`
- Tests basic PE parsing and ASCII extraction
- Validates URL, IP, and hash extraction

### **pe_overlay.exe**
- IOCs stored in overlay data appended after the PE image
- Tests overlay detection and extraction
- Ensures extractors run on overlay content

### **pe_rsrc.exe**
- IOCs embedded in `.rsrc` string tables
- Includes ASCII, UTF‑16LE, filepaths, base64, and email addresses
- Tests resource directory traversal and decoding

### **pe_utf16.exe**
- UTF‑16LE encoded strings in `.data`
- Tests wide‑string extraction and decoding
- Ensures UTF‑16LE IOCs are normalised correctly

---

## How the Integration Tests Use These Fixtures

The integration test runner:

1. Loads the manifest for each fixture.
2. Runs the `iocx` CLI on the corresponding binary.
3. Flattens all extracted IOCs across all categories.
4. Normalises:
   - lowercase filepaths
   - base64 entries (`raw` and `raw (decoded: ...)`)
5. Compares the extracted IOCs against the manifest.

A test fails if:

- any expected IOC is missing
- the CLI crashes or returns invalid JSON
- the binary parser fails to extract strings
- normalisation rules change unexpectedly

This ensures stable, deterministic behaviour across releases.

---

## Adding New Fixtures

To add a new PE fixture:

1. Compile a new binary with embedded IOCs.
2. Place it in `fixtures/bin/` as `<name>.exe`.
3. Create a manifest in `fixtures/manifests/<name>.json` with:
   - expected IOCs
   - encoding
   - location
4. Add the fixture name to the parameter list in
   `test_pe_fixtures.py`.

Fixtures should be:

- small (between 50 KB and 150 KB)
- deterministic
- reproducible
- platform‑agnostic (MinGW recommended)

---

## Philosophy

These fixtures simulate real malware samples in a controlled,
repeatable way. They allow the test suite to validate:

- binary parsing correctness
- string extraction robustness
- IOC extraction accuracy
- end‑to‑end CLI behaviour

They complement the unit tests by ensuring the entire pipeline works
on real executable files, not just synthetic strings.
