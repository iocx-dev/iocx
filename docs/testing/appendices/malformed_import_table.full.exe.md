# Appendix 3.5 – Malformed Import Table Specification

- **File:** `malformed_import_table.full.exe`
- **Layer: 3** `Adversarial`

# Purpose

A synthetically generated PE file designed to validate IOCX’s behaviour when confronted with **corrupted, out‑of‑range, or non-sensical import directory metadata**. Unlike naturally malformed binaries, this sample is constructed to contain a single, *isolated structural fault*; a deliberately invalid `IMAGE_DIRECTORY_ENTRY_IMPORT RVA`—while keeping the rest of the PE layout minimally valid. This ensures deterministic triggering of import‑related heuristics without confounding side‑effects from other PE inconsistencies.

This sample exercises IOCX’s ability to:

- detect invalid import directory RVAs
- avoid dereferencing unmapped regions
- suppress false IOCs when import parsing fails
- continue analysis gracefully despite malformed metadata

# Heuristic behaviours exercised

This sample is engineered to trigger **import‑specific structural heuristics**, including:

- **Data directory anomalies**
   - `data_directory_out_of_range`
      - Import directory RVA (`0xDEADBEEF`) lies outside all sections and beyond `SizeOfImage`.
   - `import_rva_invalid`
      - Import table points to an unmapped region with no valid descriptors.
- **Import‑related metadata inconsistencies**
   - Zero parsed imports despite non‑zero directory size.
   - Absence of import descriptors, IAT, INT, or DLL names.
- **Graceful degradation**
   - Import parsing must fail safely without producing:
      - false DLL names
      - false function names
      - synthetic IOCs
      - misaligned string extraction

# Why this sample is generated (not compiled)

No compiler or linker will emit a PE file with:

- an import directory RVA pointing to an unmapped region
- a non‑zero import directory size with no import descriptors
- a directory entry that lies beyond `SizeOfImage`
- a directory that does not map to any section

These conditions violate the PE/COFF specification and cannot be produced through normal toolchains.
This sample must therefore be **manually constructed** to guarantee deterministic import‑directory corruption.

# Contract enforced

This sample must produce **stable, deterministic** output under `analysis_level = full`, specifically:

- **metadata.imports**
   - Must be an empty list (`[]`), not partially populated or error‑contaminated.
- **analysis.heuristics**
   - Must include:
      - `data_directory_out_of_range`
      - `import_rva_invalid`
   - Metadata must include the exact invalid RVA and directory size.
- **analysis.extended**
   - Import‑related summary fields must reflect:
      - `dll_count = 0`
      - `import_count = 0`
      - `delayed_import_count = 0`
      - `bound_import_count = 0`
- **iocs**
   - No IOCs must be emitted as a side‑effect of malformed import parsing.
- **analysis.sections**
   - Section analysis must remain unaffected by the invalid import directory.

This ensures IOCX’s import‑parsing logic is **robust, deterministic, and safe**, even when confronted with adversarial PE files containing corrupted or nonsensical import directory metadata.
