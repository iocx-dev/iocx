# Appendix 3.TBD – Franken Malformed PE Specification (PE32)

- **File:** `franken_malformed_pe.pe32.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A deliberately corrupted **PE32** binary constructed to exercise IOCX’s handling of **multiple simultaneous structural violations**, including overlapping sections, misaligned raw data, contradictory optional‑header fields, invalid directory RVAs, and unmappable entrypoints. This fixture is designed to validate that IOCX can:

- parse valid structures where they exist
- reject invalid structures deterministically
- surface multiple independent anomalies
- avoid false positives in IOC extraction
- remain stable under extreme malformed conditions

This sample is the **PE32 counterpart** to `franken_malformed_pe.full.exe` (PE32+), ensuring both architecture paths are hardened against complex, multi‑vector corruption.

# Behaviours exercised

This fixture intentionally includes:

**1. Overlapping sections**
- `.text` and `.rdata` overlap in both RVA and raw file ranges
- Ensures `_analyse_section_overlap` --> `section_overlap` fires
- Also triggers an obfuscation hint: `abnormal_section_overlap`

**2. Misaligned raw section data**
- `.rdata` and `.data` have `PointerToRawData` values not aligned to `FileAlignment = 512`
- Ensures `_analyse_section_alignment` -> `section_raw_misaligned` fires for both

**3. Contradictory optional‑header size declarations**
- `SizeOfImage = 8192`
- But `.rsrc` extends beyond RVA 11776
- Ensures `_analyse_optional_header_consistency` --> `optional_header_inconsistent_size` fires

**4. Invalid entrypoint mapping**
- `AddressOfEntryPoint = 0x3000`
- No section covers this RVA
- Ensures `_analyse_entrypoint_mapping` --> `entrypoint_out_of_bounds` fires

**5. Invalid data directories**
- Import directory `RVA = 0x5000` > `SizeOfImage`
   - Ensures `data_directory_out_of_range` fires
   - Ensures `import_rva_invalid` fires
- Resource directory has `RVA = 0` but non‑zero size
   - Ensures `data_directory_zero_rva_nonzero_size` fires

**6. Valid sections still parsed**
   - `.text`, `.rdata`, `.data`, `.rsrc` all have valid headers
   - Ensures IOCX:
      - extracts section metadata
      - computes entropy
      - does not discard valid structures due to unrelated corruption

# Contract enforced

Running under `analysis_level = full`, IOCX must:

- Detect all of the following anomalies:
   - `section_overlap`
   - `section_raw_misaligned` (for `.rdata` and `.data`)
   - `optional_header_inconsistent_size`
   - `entrypoint_out_of_bounds`
   - `data_directory_out_of_range`
   - `data_directory_zero_rva_nonzero_size`
   - `import_rva_invalid`
- Not detect:
   - `tls_anomaly`
   - `signature_anomaly`
   - `packer_entropy_suspicious`
   - `section_zero_length`
   - any false‑positive IOC patterns
- Produce:
   - Four parsed sections:
      - `.text`
      - `.rdata`
      - `.data`
      - `.rsrc`
   - Valid entropy values for each section
   - No imports, exports, resources, or signatures
   - No IOC false positives
- One obfuscation hint:
   - `abnormal_section_overlap`

This ensures IOCX correctly identifies multi‑vector structural corruption in **PE32** binaries while still extracting valid metadata and maintaining deterministic behaviour.
