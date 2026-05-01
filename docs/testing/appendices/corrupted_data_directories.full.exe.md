# Appendix 3.8 – Corrupted Data Directories Specification

- **File:** `corrupted_data_directories.full.exe`
- **Layer: 3** `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s behaviour when confronted with **overlapping, out‑of‑range, and impossible data‑directory entries**. This sample isolates directory‑table corruption while keeping the rest of the PE minimally valid, ensuring deterministic triggering of directory‑related heuristics without interference from unrelated structural faults.

This file is engineered to violate multiple PE/COFF invariants relating to the **Data Directory Table**, including:

- directory RVAs extending beyond `SizeOfImage`
- overlapping directory ranges
- directory RVAs pointing to impossible or non‑canonical addresses
- declared directories with no corresponding mapped region

# Heuristic behaviours exercised

This sample is intentionally crafted to trigger **directory‑specific structural heuristics**, including:

- **Data directory out‑of‑range**
   - `data_directory_out_of_range`
      - Directory 2 (`IMAGE_DIRECTORY_ENTRY_RESOURCE`) extends beyond `SizeOfImage`.
      - Directory 3 (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`) extends beyond `SizeOfImage`.
      - Directory 4 (`IMAGE_DIRECTORY_ENTRY_SECURITY`) uses an impossible RVA (`0xFFFFFFF0`).
- **Directory overlap**
   - `data_directory_overlap`
      - Directory 2 and Directory 3 overlap in RVA space.
- **Import directory fallback**
   - `import_rva_invalid`
      - Import directory is declared but empty (`RVA = 0, Size = 0`), ensuring IOCX suppresses import parsing safely.
- **Graceful degradation**
   - Directory corruption must not:
      - cause false imports
      - produce synthetic IOCs
      - break section parsing
      - misinterpret RVA ranges

# Why this sample is generated (not compiled)

No compiler or linker will emit a PE file with:

- overlapping data directories
- directory RVAs beyond `SizeOfImage`
- directory RVAs in the non‑canonical high range (`0xFFFFFFF0`)
- declared directories with no mapped region
- contradictory directory sizes

These conditions violate the PE/COFF specification and cannot be produced through normal toolchains.
This sample must therefore be **manually constructed** to guarantee deterministic directory‑table corruption.

# Contract enforced

This sample must produce **stable, deterministic output** under `analysis_level = full`, specifically:

- **analysis.heuristics**
   - Must include:
      - `data_directory_out_of_range` (for each invalid directory)
      - `data_directory_overlap` (for overlapping directory ranges)
      - `import_rva_invalid`
   - Metadata must include the exact RVA and size values as encoded.
- **analysis.sections**
   - Section parsing must remain unaffected by directory corruption.
- **metadata**
   - No imports, exports, resources, TLS, or signatures must be inferred.
   - Section list must contain exactly one section (`.text`).
- **iocs**
   - No IOCs must be emitted as a side‑effect of corrupted directory parsing.

This ensures IOCX’s directory‑validation logic behaves predictably even when confronted with adversarial PE files containing overlapping, out‑of‑range, or impossible data‑directory entries.
