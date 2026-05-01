# IOCX — Static IOC Extraction Engine

### Official IOCX Project

This is the **official IOCX engine** for static IOC extraction and PE analysis.

- **PyPI:** https://pypi.org/project/iocx/
- **GitHub:** https://github.com/iocx-dev/iocx
- **Organisation:** https://github.com/iocx-dev
- **Website:** https://iocx.dev

IOCX is **not** an OSINT reputation checker, HTML report generator, or IP/domain scoring tool.
It is a **static analysis engine** focused on extracting Indicators of Compromise (IOCs) from binaries and text with deterministic, snapshot‑stable output.

---

## What IOCX does

IOCX is a fast, safe, deterministic engine for extracting Indicators of Compromise (IOCs) from:

- Windows PE files
- Raw text
- Logs and unstructured data

It performs **pure static analysis** — no execution, no sandboxing, no risk.

## What's new in v0.7.1

### **Bare Domain Extractor Overhaul**
- Expanded **TLD allow‑list** and strengthened **BAD_TLD deny‑list**
- Refined boundary rules to reduce false positives in noisy text
- Added **punycode decoding**, Unicode script classification, and homoglyph/confusable detection
- Hardened regex for **predictable linear performance** under adversarial input
- New metadata fields:
  - `punycode`, `punycode_decodes_to_unicode`
  - `decoded_unicode`
  - `contains_confusables`
  - `script`

### **Performance guarantees**
- **~150-300 MB/s** for individual detectors (domains, crypto, filepaths, IPs)
- **Strict linear scaling** across all detectors
- Pathological punycode, IPv6, and filepath inputs complete in **< 15 ms**
- End‑to‑end engine throughput: **20-30 MB/s**

### **Heuristic engine and adversarial fixture expansion**
- Deterministic section overlap and alignment, optional header consistency, entrypoint mapping, data directory anomalies, and import directory validity heuristics
- Adversarial fixtures covering all new heuristics and IOC subsystems.

### **Documentation updates**
- New adversarial appendices
- New Performance guarantees
- Expanded schema‑contract guidance

## Recent changes

### v0.7.0

- **Deterministic heuristic engine**

Anti‑debug APIs, TLS anomalies, packer‑like signals, RWX sections, import anomalies.

- **First adversarial samples added**

`heuristic_rich.exe`, `crypto_entropy_payload.exe`, `string_obfuscation_tricks.exe`.

- **Snapshot‑based contract testing**

Deterministic output for sections, imports, heuristics, and IOCs.

- **Rich Header crash fixed**

Deep hex‑encoding of nested byte structures prevents JSON serialization failures.

- **Documentation updates**

New appendices and deterministic‑output guidance.

### v0.6.0

- Stable JSON schema across all analysis levels
- Deterministic PE metadata (headers, TLS, optional header, signatures)
- Guaranteed IOC categories (always present, empty arrays when no matches)
- Formalised analysis levels:
  - core behaviour → no analysis block
  - basic → section layout + entropy
  - deep → adds obfuscation heuristics
  - full → extended metadata summaries
- Schema‑contract tests to prevent drift across releases

## Schema stability

IOCX guarantees a stable JSON schema across releases. JSON objects are unordered by definition, so consumers should rely on field presence and structure rather than positional ordering.

## Features

- Extracts IOCs from Windows PE files and raw text
- Detects URLs, domains, IPv4/IPv6, file paths, hashes, emails, Base64
- Crypto wallet detection (Ethereum, Bitcoin)
- Deterministic output suitable for automation and CI/CD
- Multi-level analysis depth (`basic` → `full`)
- Minimal dependencies, safe for enterprise environments
- CLI and Python API
- Binary-aware static analysis with entropy, sections, imports, TLS, signatures

## Installation

```bash
pip install iocx
```

## CLI Usage

```bash
iocx suspicious.exe
```

```bash
echo "Visit http://bad.example.com" | iocx -
```

## Python API

```python
from iocx.engine import Engine

engine = Engine()
results = engine.extract("suspicious.exe")
print(results)
```

## Why IOCX?

- Static‑only design (never executes untrusted code)
- Binary‑aware IOC extraction
- Stable, predictable JSON schema
- High performance: ~25-30 MB/s end-to-end, with individual detectors reaching 150-450 MB/s throughput)
- Ideal for DFIR, SOC automation, CI/CD, and threat‑intel pipelines

## Project identity & naming

The name **IOCX** refers specifically to this project and its associated PyPI package and repositories under the **iocx-dev** organisation.

Third‑party tools **must not**:

- Use `iocx` as their repository name
- Present themselves as the IOCX engine
- Use the PyPI badge for this package in a way that implies authorship
- Imply official affiliation or endorsement without permission

Community tools that integrate with IOCX are encouraged to use names like:

- `iocx-<plugin-name>`
- `iocx-plugin-<feature>`
- `iocx-extension-<name>`

## Extensibility

IOCX includes a lightweight plugin system for custom detectors, parsers, and transformation rules. Plugins can emit new IOC categories, override built‑in behaviour, or integrate IOCX into larger analysis pipelines.

See the documentation for details on writing detectors and plugins.

## License

MIT License
