<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-273_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/malx-labs/malx-ioc-extractor/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/malx-labs/malx-ioc-extractor" alt="License">
  </a>
  <a href="https://github.com/malx-labs/malx-ioc-extractor/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/malx-labs/malx-ioc-extractor/ci.yml?label=build" alt="Build Status">
  </a>
  <img src="https://img.shields.io/badge/v0.2.0_performance-1MB_in_0.0053s-brightgreen" alt="Performance">
  <img src="https://img.shields.io/badge/v0.2.0_throughput-~200MB%2Fs-brightgreen" alt="Throughput">
  <img src="https://img.shields.io/badge/v0.2.0_pathological_IPv6-0.0005s-brightgreen" alt="Pathological IPv6 Timing">
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

## Why malx‑ioc‑extractor?

malx‑ioc‑extractor is designed for environments where safety, determinism, and automation matter. While many IOC extractors operate only on raw text, malx‑ioc‑extractor includes binary‑aware static analysis and an extensible rule system, making it suitable for DFIR pipelines, CI systems, and high‑volume threat‑intel processing.

**Key advantages**

- **Static‑only design** — no execution, no sandboxing, and no risk of running untrusted code
- **Binary parsing** — extracts indicators from Windows PE files in addition to raw text
- **Deterministic behaviour** — stable output and predictable performance, ideal for automated workflows
- **Extensible rule engine** — plug in custom detectors, parsers, and enrichment logic
- **Consistent JSON schema** — uniform output that integrates cleanly with SIEM, SOAR, and log pipelines
- **Low dependency footprint** — minimal attack surface and safe for enterprise environments
- **Designed for pipelines** — fast start‑up, fast throughput, and no heavyweight runtime requirements

## Use Cases

malx‑ioc‑extractor fits naturally into DFIR, security automation, and threat‑intelligence workflows. Typical usage patterns include:

### SOC & Incident Response
- Extract indicators from suspicious emails, alerts, or analyst clipboard text
- Parse IOCs from incident reports and triage notes into structured JSON
- Safely inspect malware samples statically without executing anything

### Threat Intelligence Processing
- Normalize indicators from threat‑intel feeds
- Batch‑process dumps of unstructured text into machine‑readable IOC sets
- Build enrichment pipelines on top of the deterministic output format

### CI/CD & DevSecOps
- Scan new binaries for embedded indicators before publishing artifacts
- Integrate IOC extraction into automated security checks
- Detect accidental inclusion of URLs or addresses during build steps

### Bulk Automation & Scripting
- Pipe logs, artifacts, or telemetry through malx‑ioc‑extractor to extract actionable indicators
- Use the Python API for batch workflows, ETL pipelines, or custom tooling
- Combine with rule extensions to tailor detection to internal patterns or datasets

## v0.3.0 — Stronger Architecture, New Crypto IOC Detection, Same Blazing Performance

Version 0.3.0 is a foundational release that tightens the engine’s architecture, expands IOC coverage with Ethereum and Bitcoin wallet detection, and preserves the extractor’s extremely fast performance even on multi‑megabyte inputs. This release makes the engine more predictable, extensible, and resilient for the long-term extensibility.

## v0.2.0 — High‑Reliability IP Detection in Hostile Data

Version 0.2.0 significantly improves IPv4/IPv6 extraction in noisy, malformed, mixed-content environments — the kind often seen in:

- SIEM log lines
- network captures
- DFIR corpus samples
- pasted analyst dumps

### Real CLI Output (Chaos Corpus Sample)

```json
$ iocx chaos_corpus.json
{
  "file": "examples/samples/structured/chaos_corpus.json",
  "type": "text",
  "iocs": {
    "urls": [
      "http://[2001:db8::1]:443"
    ],
    "domains": [],
    "ips": [
      "2001:db8::1",
      "2001:db8::1:443",
      "10.0.0.1",
      "192.168.1.10",
      "fe80::dead:beef%eth0",
      "1.2.3.4",
      "fe80::1%eth0",
      "192.168.1.110",
      "fe80::1%eth0fe80",
      "::2%eth1",
      "2001:db8::"
    ],
    "hashes": [],
    "emails": [],
    "filepaths": [],
    "base64": []
  },
  "metadata": {}
}

```
<details>
<summary><strong>Chaos Corpus: Input → Extracted Output → Explanation</strong></summary>
<br>

| Input                                 | Extracted Output                         | Explanation                                 |
|---------------------------------------|------------------------------------------|---------------------------------------------|
| fe80::dead:beef%eth0/garbage          | fe80::dead:beef%eth0                     | Salvaged valid IPv6, junk ignored.          |
| xxx192.168.1.10yyy                    | 192.168.1.10                             | IPv4 inside junk text.                      |
| DROP:client=10.0.0.1;;;ERR            | 10.0.0.1                                 | IPv4 from noisy log field.                  |
| [2001:db8::1]::::443                  | 2001:db8::1                              | IPv6 and IPv6+port extracted.               |
|                                       | 2001:db8::1:443                          |                                             |
| GET http://[2001:db8::1]:443/index    | http://[2001:db8::1]:443                 | URL with IPv6 parsed correctly.             |
| udp://[fe80::1%eth0]::::53            | fe80::1%eth0                             | Concatenated IPv6 split up.                 |
| 192.168.1.110.0.0.1                   | 192.168.1.110                            | Combined IP segment salvaged.               |
| fe80::1%eth0fe80::2%eth1              | fe80::1%eth0fe80, ::2%eth1               | Concatenated IPv6 split up.                 |
| 2001:db8::12001:db8::2                | 2001:db8::                               | Longest valid IPv6 prefix found.            |
| 256.256.256:256                       | —                                        | Invalid indicator ignored.                  |
</details>

<details>
<summary><strong>Performance Benchmarks (v0.2.0)</strong></summary>
<br>

All measurements from the latest performance suite:

| Sample Type	               | Time     |
|------------------------------|----------|
| 1 MB mixed‑content sample	   | 0.0053s  |
| Pathological IPv6 blob	   | 0.0055s  |
| 100 KB sample	               | 0.0006s  |
| 300 KB sample	               | 0.0017s  |
| 600 KB sample	               | 0.0031s  |
| 1 MB sample	               | 0.0055s  |

- **Throughput:** ~200 MB/s
- **Worst‑case IPv6 blob:** ~0.5 ms
- **Linear scaling:** almost perfect from 100 KB → 1 MB
</details>

<details>
<summary><strong>Performance Benchmarks (v0.3.0)</strong></summary>
<br>

All measurements from the latest performance suite:

| Sample Type	               | Time     |
|------------------------------|----------|
| IP                           |          |
|==============================|==========|
| 1 MB mixed‑content sample	   | 0.0070s  |
| Pathological IPv6 blob	   | 0.0004s  |
| 100 KB sample	               | 0.0008s  |
| 300 KB sample	               | 0.0021s  |
| 600 KB sample	               | 0.0038s  |
| 1 MB sample	               | 0.0068s  |
|------------------------------|----------|
| Filepath                     |          |
|==============================|==========|
| 1 MB mixed‑content sample	   | 0.0040s  |
| Pathological deep unix path  | 0.0237s  |
| 300 KB sample	               | 0.0011s  |
| 600 KB sample	               | 0.0022s  |
| 1000 KB sample               | 0.0038s  |
| 1500 KB sample	           | 0.0055s  |
|------------------------------|----------|
| Crypto                       |          |
|==============================|==========|
| 1 MB mixed‑content sample	   | 0.0021s  |
| Pathological ETH-like blob   | 0.0012s  |
| 300 KB sample	               | 0.0006s  |
| 600 KB sample	               | 0.0012s  |
| 1000 KB sample               | 0.0020s  |
| 1500 KB sample	           | 0.0031s  |

- **Throughput:** ~200 MB/s
- **Worst‑case IPv6 blob:** ~0.5 ms
- **Worst‑case filepath blob:** ~23 ms
- **Worst‑case crypto blob:** ~1 ms
- **Linear scaling:** almost perfect from 100 KB → 1 MB
</details>

## Features

### IOC Extraction

- Windows PE files (.exe, .dll)
- Raw text
- Extracted strings from binaries
- Caching for increased performance

### Detections

- URLs
- Domains
- IPv4 / IPv6 addresses
- File paths
- Hashes (MD5 / SHA1 / SHA256 / SHA512 / Generic Hex)
- Email addresses
- Base64
- Crypto wallets (Ethereum, Bitcoin) (new in v0.3.0)

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

### Extract from a log file
```bash

iocx alerts.log

```

### Python API
```python

from iocx.engine import Engine

engine = Engine()
results = engine.extract("suspicious.exe")
print(results)

```
<details>
<summary><strong>Show Example JSON Output</strong></summary>

<br>

```json

{
  "file": "suspicious.exe",
  "type": "PE",
  "iocs": {
    "urls": ["http://malicious.example.com"],
    "domains": ["malicious.example.com"],
    "ips": ["45.77.12.34"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    "emails": ["attacker@example.com"],
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
      ".reloc"
    ],
    "resource_strings": [
      "C:\\Windows\\System32\\cmd.exe",
      "\\\\SERVER01\\share\\dropper.exe",
      "/home/alice/.config/evil.sh@%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"
    ]
  }
}

```

</details>

## Architecture
```plaintext

malx-ioc-extractor/
│
├── examples/        # Sample files + generators
├── tests/           # Unit and integration tests
├── iocx
    ├── detectors/   # Regex-based IOC detectors
    ├── parsers/     # PE parsing, string extraction
    ├── cli/         # Command-line interface

```

The engine is intentionally modular so components can be extended or replaced easily.

## Extending the Engine

You can add custom:

- Regex detectors
- File parsers
- Normalisation logic

### Register a custom detector
As an example, the following detector extracts the word "SECRET" from a string of text:
```python

import re
from iocx.models import Detection
from iocx.detectors.registry import register_detector

SECRET_REGEX = re.compile(r"\bSECRET\b")

@register_detector("custom.secret")
def detect_secret(text: str):
    results = []
    for m in SECRET_REGEX.finditer(text):
        results.append(
            Detection(
                value=m.group(0),
                start=m.start(),
                end=m.end(),
                category="custom.secret"
            )
        )
    return results

```
Assuming the detector was saved as `my_detector.py`, consume the custom detector - if the detector fires, its results will be added to the list of detected IOCs:
```python

from iocx.engine import Engine
import my_detector

engine = Engine()

results = engine.extract("This is a SECRET message.")
print(results)

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
