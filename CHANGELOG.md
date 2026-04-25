# v0.7.1 — Heuristics Engine Expansion & Structural Analysis Improvements

**Released: 2026‑04‑22**

## Added

- Deterministic heuristics engine for PE data directory validation:
   - data_directory_out_of_range
   - data_directory_zero_rva_nonzero_size
   - data_directory_overlap
   - import_rva_invalid
- Entrypoint range validation and optional header consistency checks.
- TLS directory anomaly detection.
- Internal data_directories analysis (not exposed in public output).
- Adversarial testing layer to validate extraction accuracy and structural anomaly detection.

## Changed

- Heuristics now receive a unified internal analysis structure (`sections` + `data_directories`).
- Public output remains stable except where new heuristics apply.
- Improved section overlap detection and RVA range validation.

### Crypto Extractor Improvements

- Added **Base58Check checksum validation** for legacy BTC addresses
- Prevented extraction of near‑miss or malformed BTC Base58 strings
- ETH extraction unchanged (already strict and correct)

This change significantly reduces false positives in BTC detection and aligns behaviour with the v0.7.1 adversarial requirements.

## Fixed

- Removed internal fields (raw_address, virtual_address) from public section output.
- Prevented internal data_directories from leaking into metadata.
- Improved stability when parsing malformed or adversarial PE files.

## Notes

- Updated contract snapshot for `heuristic_rich.full.exe` to reflect new heuristics.
- The previous snapshot predates directory‑range and RVA‑validation logic.

# v0.6.0 — Internal Improvements & Stability Work

(Retrospective summary)

- Improved PE parsing robustness.
- Added extended metadata extraction.
- Added obfuscation detection layer.
- Expanded contract test coverage.
- General performance and stability improvements.

# v0.5.0 — IOC Extraction Engine Enhancements

(Retrospective summary)

- Improved URL, domain, IP, and hash extraction.
- Added base64 and cryptocurrency IOC detection.
- Introduced layered analysis modes (basic, deep, full).

# v0.4.0 and earlier — Initial Development

(Retrospective summary)

- Initial PE parsing pipeline.
- First version of IOC extraction.
- Core CLI and engine structure.
