# Appendix 3.10 – UPX Name Only Specification

- **File:** `upx_name_only.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s **false‑positive suppression** for packer heuristics. This sample includes UPX‑like section names but no high entropy, no overlay, and no packer‑like structures. It is the **negative** counterpart to `packed_lookalike.full.exe`.

Together, these two fixtures form a positive/negative pair that ensures IOCX’s packer heuristics are both **sensitive** and **specific**.

# Behaviours exercised

This fixture intentionally includes:

- **UPX‑like section names**
   - `.upx0` and `.upx1`
   - Ensures `_analyse_packer` --> `packer_section_name` fires
   - Confirms IOCX does not require entropy to trigger name‑based heuristics
- **Low‑entropy `.text` section**
   - Mostly zeros with a single RET
   - Ensures `_analyse_packer` does not fire `high_entropy_section`
- **No overlay**
   - Ensures IOCX does not detect false packer signatures
- **Valid section layout**
   - Section VA ranges fit within `SizeOfImage`
   - Ensures `_analyse_optional_header_consistency` does not fire
- **Empty import directory**
   - Ensures `_analyse_import_directory_validity` --> `import_rva_invalid` fires

# Contract enforced

Under `analysis_level = full`, IOCX must:

- Detect:
   - `packer_suspected` (packer section names)
   - `import_rva_invalid`

- Not detect:
   - `packer_suspected` (high entropy)
   - Any optional‑header inconsistencies
   - Any section overlap
   - Any section alignment issues
   - Any overlay‑related anomalies

This ensures IOCX does not misclassify low‑entropy, UPX‑named binaries as packed.
