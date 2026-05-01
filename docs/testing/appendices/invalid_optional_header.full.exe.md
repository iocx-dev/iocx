# Appendix 3.14 – Invalid Optional Header Specification (PE32+)

- **File:** `invalid_optional_header.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetically malformed PE32+ binary designed to validate IOCX’s handling of **corrupted optional‑header fields**, including impossible alignments, contradictory size declarations, and out‑of‑range directory RVAs. This fixture ensures IOCX does not trust optional‑header metadata blindly and instead applies strict structural validation while maintaining deterministic, JSON‑safe behaviour.

This sample is the **PE32+ counterpart** to the PE32 variant (`invalid_optional_header.pe32.full.exe`), ensuring architecture‑specific parsing paths are independently hardened.

# Behaviours exercised

This fixture intentionally includes:

- **Invalid `AddressOfEntryPoint``**
   - EP RVA points far outside any section
   - Ensures `_analyse_entrypoint_mapping` --> `entrypoint_out_of_bounds` fires *if* section parsing succeeds
   - In this PE32+ variant, no sections are valid, so only directory‑based heuristics fire
- **Invalid `ImageBase`**
   - Non‑canonical, non‑aligned value
   - Must be surfaced verbatim in metadata
- **Invalid alignment rules**
   - `FileAlignment = 0x4000` > `SectionAlignment = 0x1000`
   - Must not cause section parsing attempts or misalignment heuristics (no valid sections exist)
- **Contradictory size declarations**
   - `SizeOfImage = 0x200`
   - `SizeOfHeaders = 0x800`
   - Must not cause crashes or phantom sections
- **Directory RVAs outside the image**
   - Export directory RVA > `SizeOfImage`
   - Ensures `_analyse_data_directory_anomalies` -> `data_directory_out_of_range` fires
- **Declared directory count smaller than actual table**
   - Ensures IOCX respects `NumberOfRvaAndSizes` and does not read beyond declared entries

# Contract enforced

Running under `analysis_level = full`, IOCX must:

- Detect:
   - `data_directory_out_of_range`
- Not detect:
   - `section_raw_misaligned`
   - `section_overlap`
   - `optional_header_inconsistent_size`
   - `entrypoint_out_of_bounds`
   - any import/resource/TLS anomalies
- Produce:
   - No sections
   - No imports
   - No resources
   - No false‑positive IOCs

This ensures IOCX correctly identifies optional‑header corruption in **PE32+** binaries without misinterpreting or over‑parsing invalid structures.
