# Appendix 3.9 – Truncated Rich Header Specification

- **File:** `truncated_rich_header.full.exe`
- **Layer: 3** `Adversarial`

# Purpose

A synthetically constructed PE file designed to validate IOCX’s behaviour when encountering a **corrupted, truncated, or partially overwritten Rich header** in the DOS stub region. The Rich header is not part of the PE/COFF specification and is ignored by the Windows loader, but malformed Rich data can confuse tools that attempt to parse compiler metadata. This sample ensures IOCX handles malformed Rich headers safely and deterministically without producing false positives or structural anomalies.

The file deliberately embeds:

- a fake Rich signature (`"Rich"`)
- a block of NOPs and INT3 bytes
- a forced truncation by seeking into the middle of the Rich blob
- a valid PE header immediately after the truncated region

This isolates Rich‑header corruption while keeping the rest of the PE structure valid.

# Heuristic behaviours exercised

This sample is engineered to confirm that IOCX:

- **Does not misinterpret malformed Rich data**
   - `rich_header` must resolve to null
   - No Rich metadata must be inferred
- **Does not treat Rich corruption as a structural anomaly**
   - No `pe_structure_anomaly` should fire due to Rich truncation
- **Continues normal PE parsing**
   - Section table, optional header, and directory parsing must remain unaffected
- **Triggers only relevant heuristics**
   - `import_rva_invalid` (because the import directory is zeroed)

This ensures IOCX’s Rich‑header handling is robust, safe, and non‑intrusive.

# Why this sample is generated (not compiled)

No compiler or linker will emit a PE file with:

- a truncated Rich header
- a Rich signature overwritten mid‑stream
- a DOS stub partially overwritten after writing Rich metadata
- an intentionally corrupted Rich XOR region

These conditions violate the internal structure of MSVC’s Rich metadata but do not violate the PE/COFF specification.
This sample must therefore be **manually constructed** to guarantee deterministic Rich‑header corruption.

# Contract enforced

This sample must produce **stable, deterministic** output under `analysis_level = full`, specifically:

- **metadata.rich_header**
   - Must be `null` (no valid Rich header detected)
- **analysis.heuristics**
   - Must include:
      - `import_rva_invalid` (due to empty import directory)
   - Must *not* include:
      - any Rich‑header‑related anomalies
      - any structural anomalies caused by the truncated Rich blob
- **analysis.sections**
   - Must correctly parse the `.text` section
- **metadata**
   - No imports, exports, resources, TLS, or signatures must be inferred

This ensures IOCX handles malformed Rich headers safely without misclassification or structural misinterpretation.
