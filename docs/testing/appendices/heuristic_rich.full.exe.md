# Appendix 3.1 - Heuristic‑Rich Sample Specification

- **File:** `heuristic_rich.full.exe`
- **Layer: 3** — `Adversarial`

## Purpose

A deliberately constructed PE file used to validate deterministic behaviour of IOCX’s full‑analysis heuristic engine.

## Heuristic behaviours exercised

- Anti‑debug API imports (`CheckRemoteDebuggerPresent`, `IsDebuggerPresent`, `OutputDebugStringA`, timing APIs)
- TLS callback anomaly (callback outside declared TLS directory range)
- Packer‑like section (`UPX0`)
- RWX section and abnormal `.bss` layout (virtual‑only)
- Mixed entropy sections (high, low, and zero entropy)
- Large, noisy import table across multiple DLLs
- Network IOCs (URL, domain, IP)
- Full extended metadata (imports, TLS, headers, optional header)

## Contract enforced

This sample must produce a stable, deterministic output when analysed with analysis_level = full, including:

- analysis.sections
- analysis.obfuscation
- analysis.extended
- analysis.heuristics
- All structural metadata and IOCs
