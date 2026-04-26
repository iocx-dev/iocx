# Appendix 3.TBD – Invalid Optional Header Specification (PE32)

- **File:** `invalid_optional_header.pe32.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A malformed **PE32** binary crafted to validate IOCX’s architecture‑specific handling of **invalid optional‑header fields**, including broken alignment rules, contradictory size declarations, and out‑of‑range directory RVAs. Unlike the PE32+ variant, this fixture contains one minimally valid section, ensuring IOCX can parse valid structures while rejecting invalid ones.

This sample is the **PE32 counterpart** to `invalid_optional_header.full.exe`, ensuring both parsing paths behave consistently but independently.

# Behaviours exercised

This fixture intentionally includes:

- **Invalid `AddressOfEntryPoint`**
   - EP RVA far outside any section
   - Ensures `_analyse_entrypoint_mapping` --> `entrypoint_out_of_bounds` fires
- **Invalid `ImageBase`**
   - Small, non‑aligned value
   - Must be surfaced verbatim
- **Invalid alignment rules**
   - `FileAlignment = 0x4000`
   - `.text` raw pointer = `0x200` (not aligned)
   - Ensures `_analyse_section_alignment` -> `section_raw_misaligned` fires
- **Contradictory size declarations**
   - `SizeOfImage = 0x200`
   - `.text` ends at RVA `0x2000`
   - Ensures `_analyse_optional_header_consistency` --> `optional_header_inconsistent_size` fires
- **Directory RVAs outside the image**
   - Export directory RVA > `SizeOfImage`
   - Ensures `_analyse_data_directory_anomalies` -> `data_directory_out_of_range` fires
- **Valid `.text` section**
   - Ensures IOCX:
      - parses valid sections
      - computes entropy
      - does not misclassify the entire file as unreadable

# Contract enforced

Running under `analysis_level = full`, IOCX must:

- Detect:
   - `section_raw_misaligned`
   - `optional_header_inconsistent_size`
   - `entrypoint_out_of_bounds`
   - `data_directory_out_of_range
- Not detect:
   - `section_overlap`
   - `import_rva_invalid`
   - `tls_anomaly`
   - any packer or signature heuristics
- Produce:
   - Exactly **one** parsed section (`.text`)
   - Valid entropy for `.text`
   - No imports, resources, or signatures
   - No false‑positive IOCs

This ensures IOCX correctly identifies optional‑header corruption in **PE32** binaries while still parsing valid sections and maintaining deterministic behaviour.
