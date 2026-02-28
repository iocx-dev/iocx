<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-246_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/malx-labs/malx-ioc-extractor/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/malx-labs/malx-ioc-extractor" alt="License">
  </a>
  <a href="https://github.com/malx-labs/malx-ioc-extractor/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/malx-labs/malx-ioc-extractor/ci.yml?label=build" alt="Build Status">
  </a>
</p>

# malx‑ioc‑extractor

**Static IOC extraction for binaries, text, and artifacts — fast, safe, and open‑source.**

malx‑ioc‑extractor is a lightweight, extensible engine for extracting Indicators of Compromise (IOCs) using pure static analysis. No execution. No sandboxing. No risk.
Built for DFIR workflows, SOC automation, and large‑scale threat analysis.

It’s designed to be:

- **Safe** — never executes untrusted code
- **Fast** — built for automation and pipelines
- **Extensible** — plug in your own regexes, parsers, and rules
- **Developer‑friendly** — clean API, CLI, and examples
- **Open‑source** — the extraction engine is free; enrichment lives in the MalX cloud platform

This project is the foundation of the MalX Labs ecosystem for scalable, modern threat‑analysis tooling.

## Features

### IOC Extraction

- Windows PE files (.exe, .dll)
- Raw text
- Extracted strings from binaries

### Detections

- URLs
- Domains
- IPv4 / IPv6 addresses
- File paths
- Hashes (MD5 / SHA1 / SHA256)
- Email addresses
- Base64

### Static PE Parsing

- Imports
- Sections
- Resources
- Metadata

### Developer‑Friendly

- Clean JSON output
- CLI + Python API
- Modular, extensible rule system
- Minimal dependency footprint

### Security‑First

- Zero malware execution
- Safe for untrusted input
- Deterministic behaviour

### Why Static Only?

Static analysis ensures safety, determinism, and CI‑friendly operation. No sandboxing, no execution, and no risk of triggering malware behaviour.

## Quickstart

### Install
```bash

pip install iocx

```

### Extract IOCs from a file
```bash

iocx suspicious.exe

```

### Extract from text
```bash

echo "Visit http://bad.example.com" | iocx -

```

### Python API
```python

from iocx import extract

results = extract("suspicious.exe")
print(results)

```

## Example Output
```json

{
  "file": "suspicious.exe",
  "type": "PE",
  "iocs": {
    "urls": ["http://malicious.example.com"],
    "domains": ["malicious.example.com"],
    "ips": ["45.77.12.34"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    "emails": [],
    "filepaths": [
      "c:\\windows\\system32\\cmd.exe",
      "d:\\temp\\payload.bin"
    ],
    "base64": []
  },
  "metadata" : {
    "file_type": "PE",
    "imports": [
      "KERNEL32.dll",
      "msvcrt.dll"
    ],
    "sections": [
      ".text",
      ".data",
      ".rdata",
      ".pdata",
      ".xdata",
      ".bss",
      ".idata",
      ".CRT",
      ".tls",
      ".reloc",
      "/4",
      "/19",
      "/31",
      "/45",
      "/57",
      "/70",
      "/81",
      "/97",
      "/113"
    ],
    "resource_strings": []
  }
}

```

## Architecture
```plaintext

malx-ioc-extractor/
│
├── examples/        # Sample files + generators
├── tests/           # Unit and integration tests
├── iocx
    ├── extractors/  # Regex-based IOC detectors
    ├── parsers/     # PE parsing, string extraction
    ├── validators/  # Normalisation + dedupe
    ├── cli/         # Command-line interface

```

The engine is intentionally modular so components can be extended or replaced easily.

## Extending the Engine

You can add custom:

- Regex detectors
- File parsers
- Normalisation logic

Example: register a custom detector. The second argument is a detector function (a callable that receives the input and returns extracted values):
```python

from iocx.detectors import register_detector

def extract(data):
    # custom extraction logic here
    return ["wallet123"]

register_detector("crypto_wallet", extract)

```

## Safe Testing (No Malware Required)

All test samples are:

- Synthetic
- Benign
- Publicly safe (EICAR, GTUBE)
- Designed to avoid accidental malware handling

## Contributing

We welcome:

- New IOC detectors
- Parser improvements
- Bug reports
- Documentation updates
- Synthetic test samples

See CONTRIBUTING.md for full guidelines.

## Security

If you discover a security issue, do not open a GitHub issue.
Please follow the instructions in SECURITY.md.

## Related Projects (MalX Labs)

- malx-core — foundational primitives
- malx-utils — shared utilities
- malx-sandbox — dynamic analysis environment
- malx-forge — adversarial payload tooling
- malx-archive — research + PoCs

## License

Licensed under the MIT License. See LICENSE for details.
