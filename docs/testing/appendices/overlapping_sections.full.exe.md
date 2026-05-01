# Appendix 3.13 – Overlapping Sections Specification

- **File:** `overlapping_sections.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s handling of **overlapping sections, invalid virtual/raw size relationships, and inconsistent optional‑header sizing**. This fixture deliberately creates contradictory section layouts that violate PE/COFF structural rules, ensuring IOCX’s structural‑anomaly heuristics behave predictably and safely.

This sample is the **overlap‑focused counterpart** to `broken_rva_addresses.full.exe`, which exercises invalid RVAs and zero‑length regions.

# Behaviours exercised

This fixture intentionally includes:

- **Overlapping virtual address ranges**
   - `.text` covers `0x1000` -> `0x3000`
   - `.data` covers `0x1800` -> `0x3800`
   - Ensures `_analyse_section_overlap` fires
- **Overlapping raw file ranges**
   - `.text` raw: `0x200` -> `0x2200`
   - `.data` raw: `0x1000` -> `0x4000`
   - Confirms IOCX detects raw‑range overlap as well
- **Invalid virtual‑size vs raw‑size relationship**
   - `.data` has `SizeOfRawData` > `VirtualSize`
   - Ensures IOCX does not misinterpret the section as valid
- **Optional header inconsistency**
   - `SizeOfImage` = `0x3000` but `.data` ends at `0x3800`
   - Ensures `_analyse_optional_header_consistency` fires
- **Empty import directory**
   - Ensures `_analyse_import_directory_validity` --> `import_rva_invalid` fires

# Contract enforced

Under `analysis_level = full`, IOCX must:

- Detect:
   - `section_overlap`
   - `optional_header_inconsistent_size`
   - `import_rva_invalid`
- Not detect:
   - `data_directory_out_of_range`
   - `section_raw_misaligned`
   - `entrypoint_out_of_bounds`
   - any packer, TLS, or signature anomalies

This ensures IOCX correctly identifies overlapping and size‑related structural anomalies without misclassifying unrelated fields.
