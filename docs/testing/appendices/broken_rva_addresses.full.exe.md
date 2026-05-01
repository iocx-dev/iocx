# Appendix 3.12 – Broken RVA Addresses Specification

- **File:** `broken_rva_addresses.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s handling of **invalid RVAs, unmapped regions, and zero‑length sections**. This fixture deliberately introduces multiple forms of broken addressing while keeping the rest of the PE structure valid. It ensures IOCX’s RVA‑mapping logic is robust, deterministic, and capable of distinguishing between benign edge cases and genuine structural anomalies.

This sample is the **RVA‑focused counterpart** to `overlapping_sections.full.exe`, which exercises overlapping and size‑related anomalies.

# Behaviours exercised

This fixture intentionally includes:

- **Directory RVAs pointing outside the image**
   - Import directory RVA = `0x9000` while `SizeOfImage = 0x4000`
   - Ensures `_analyse_data_directory_anomalies` ---> `data_directory_out_of_range` fires
- **Directory RVAs pointing into a zero‑length section**
   - A second directory entry points into `.zero`, which has `VirtualSize = 0`
   - Ensures `_analyse_import_directory_validity` -> `import_rva_invalid` fires
- **Zero‑length section definition**
   - `.zero` has:
      - `VirtualSize = 0`
      - `SizeOfRawData = 0`
      - `PointerToRawData = 0`
   - Confirms IOCX tolerates zero‑length sections without misclassification
- **Valid section alignment and entrypoint mapping**
   - Ensures no unrelated heuristics fire

# Contract enforced

Running under `analysis_level = full`, IOCX must:

- Detect:
   - `data_directory_out_of_range`
   - `import_rva_invalid`
- Not detect:
   - `section_overlap`
   - `section_raw_misaligned`
   - `optional_header_inconsistent_size`
   - `entrypoint_out_of_bounds`
   - any packer, TLS, or signature anomalies

This ensures IOCX correctly identifies broken RVA/addressing conditions without producing false positives.
