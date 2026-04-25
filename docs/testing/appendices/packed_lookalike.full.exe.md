# Appendix 3.9 – Packed Lookalike Specification

- **File:** `packed_lookalike.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s handling of **deceptively packer‑like binaries**. This sample intentionally mimics several characteristics commonly associated with packed executables, while avoiding any real packer structures. It is used to confirm that IOCX’s packer heuristics fire **only** when the entropy and section‑name conditions are met, and that the engine does not misinterpret benign overlays or fake signatures as structural anomalies.

This sample is the **positive case** in a paired test with `upx_name_only.full.exe`.
Where the negative sample tests suppression, this sample tests **activation** of packer heuristics.

# Behaviours exercised

This fixture intentionally includes:

- **High‑entropy `.text` section**
   - 8 KB of deterministic pseudo‑random bytes
   - Entropy > 7.5 to exceed the packer threshold
   - Ensures `_analyse_packer` --> `high_entropy_section` fires
- **Fake packer section names**
   - `.upx0` and `.upx1`
   - No UPX header, no stub, no relocation table
   - Ensures `_analyse_packer` -> `packer_section_name` fires
- **Compressed‑looking overlay**
   - High‑entropy blob appended after the last section
   - Contains gzip‑like magic and “UPX!” signature
   - Not referenced by any section
   - Ensures IOCX does not misinterpret overlays as packer structures
- **Valid PE structure with deliberate optional‑header mismatch**
   - Section VA ranges exceed `SizeOfImage`
   - Ensures `_analyse_optional_header_consistency` fires
- **Empty import directory**
   - Ensures `_analyse_import_directory_validity` ---> `import_rva_invalid` fires

# Contract enforced

Under `analysis_level = full`, IOCX must:

- Detect:
   - `packer_suspected` (high entropy)
   - `packer_suspected` (packer section names)
   - `optional_header_inconsistent_size`
   - `import_rva_invalid`
- Not detect:
   - Any TLS anomalies
   - Any section overlap
   - Any section alignment issues
   - Any false packer signatures from the overlay
   - Any resource or signature anomalies

This ensures IOCX’s packer heuristics behave correctly when confronted with binaries that look packed but are not.
