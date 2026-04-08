<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-313_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/iocx-dev/iocx/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/iocx-dev/iocx" alt="License">
  </a>
  <a href="https://github.com/iocx-dev/iocx/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/iocx-dev/iocx/ci.yml?label=build" alt="Build Status">
  </a>
  <img src="https://img.shields.io/badge/v0.2.0_performance-1MB_in_0.0053s-brightgreen" alt="Performance">
  <img src="https://img.shields.io/badge/v0.2.0_throughput-~200MB%2Fs-brightgreen" alt="Throughput">
  <img src="https://img.shields.io/badge/v0.2.0_pathological_IPv6-0.0005s-brightgreen" alt="Pathological IPv6 Timing">
</p>

# Official IOCX Project

This is the **original IOCX engine** for static IOC extraction and PE analysis.
- PyPI: [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)
- Github: [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)
- Website: [https://iocx.dev/](https://iocx.dev/)

Any other repositories using the name "iocx" are **not affiliated** with this project.

# IOCX — Static IOC Extraction for Binaries, Text, and Artifacts

**Fast, safe, deterministic IOC extraction for DFIR, SOC automation, and large-scale threat analysis.**

IOCX is a lightweight, extensible engine for extracting Indicators of Compromise (IOCs) using **pure static analysis**. No execution. No sandboxing. No risk.

Built for:

- DFIR workflows
- SOC automation
- Threat-intel pipelines
- CI/CD security checks
- Large‑scale batch processing

This project is the foundation of the MalX Labs ecosystem for scalable, modern threat‑analysis tooling.

## Why IOCX?

IOCX is designed for environments where **safety, determinism, and automation** matter. Unlike extractors that operate only on raw text, IOCX includes **binary‑aware static analysis**, a **plugin-friendly rule system**, and a **stable JSON schema**.

### Key advantages

- **Static‑only design** — never executes untrusted code
- **Binary parsing** — extracts IOCs from Windows PE files in addition to raw text
- **Deterministic behaviour** — stable output and predictable performance, ideal for pipelines
- **Extensible rule engine** — custom detectors, parsers, and plugins
- **Consistent JSON schema** — clean integration with SIEM/SOAR
- **Low dependency footprint** — safe for enterprise environments
- **Pipeline-ready** — fast start‑up, fast throughput

---

## What IOCX *Is Not*

To avoid confusion:

- Not a sandbox
- Not a malware emulator
- Not a behavioural analysis tool
- Not an enrichment engine (that lives in the MalX Cloud platform)

IOCX is **static extraction only**, by design.

## Use Cases

### SOC & Incident Response
- Extract indicators from emails, alerts, or analyst clipboard text
- Parse IOCs from reports into structured JSON
- Safely inspect malware samples without execution

### Threat Intelligence Processing
- Normalize indicators from feeds
- Batch‑process unstructured text
- Build enrichment pipelines on top of deterministic output

### CI/CD & DevSecOps
- Scan binaries for embedded indicators before publishing
- Integrate IOC extraction into automated checks
- Detect accidental inclusion of URLs or addresses in builds

### Bulk Automation & Scripting
- Pipe logs or artifacts through IOCX
- Use the Python API for ETL or batch workflows
- Extend with custom detectors for internal patterns

## Version Highlights

### v0.3.0 — Stronger Architecture, New Crypto IOC Detection

- Ethereum & Bitcoin wallet detection
- Improved architecture for long-term extensibility
- Same blazing performance on multi-MB inputs

### v0.2.0 — High‑Reliability IP Detection

Significant improvements to IPv4/IPv6 extraction in noisy, malformed, mixed-content environments

## Real CLI Output (Chaos Corpus Sample)

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
|            **IP**            |          |
| 1 MB mixed‑content sample	   | 0.0070s  |
| Pathological IPv6 blob	   | 0.0004s  |
| 100 KB sample	               | 0.0008s  |
| 300 KB sample	               | 0.0021s  |
| 600 KB sample	               | 0.0038s  |
| 1 MB sample	               | 0.0068s  |
|         **Filepath**         |          |
| 1 MB mixed‑content sample	   | 0.0040s  |
| Pathological deep unix path  | 0.0237s  |
| 300 KB sample	               | 0.0011s  |
| 600 KB sample	               | 0.0022s  |
| 1000 KB sample               | 0.0038s  |
| 1500 KB sample	           | 0.0055s  |
|           **Crypto**         |          |
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

## Project Identity & Naming

IOCX is the name of the official static IOC extraction engine published on:

- **PyPI**: https://pypi.org/project/iocx/
- **GitHub**: https://github.com/iocx-dev/iocx

The IOCX name, branding, and project identity refer **exclusively** to this project and its associated packages, documentation, and releases.

To protect users from confusion and maintain a healthy ecosystem:

### What third‑party projects may NOT do

- Use `iocx` as the name of their repository
- Publish tools named “iocx” that are not this project
- Present themselves as the creators or maintainers of IOCX
- Use the PyPI badge for the official `iocx` package
- Imply official affiliation or endorsement without permission

These actions mislead users and violate the identity of the project.

### Allowed & encouraged

Third‑party tools, plugins, and integrations are welcome.
To avoid confusion, they should follow this naming pattern:

- `iocx-<plugin-name>`
- `iocx-plugin-<feature>`
- `iocx-extension-<name>`

Examples:

- `iocx-osint-enricher`
- `iocx-detector-custom`

### Why this matters

IOCX is used in DFIR, SOC automation, CI/CD pipelines, and threat‑intel workflows.
Clear naming ensures:

- Users know which tool is the **official** IOCX engine
- Third‑party tools are discoverable without causing confusion
- The ecosystem grows in a structured, healthy way

If you are building something that integrates with IOCX and want guidance on naming or attribution, feel free to open an issue

## Official IOCX Repositories

- Core Engine: https://github.com/iocx-dev/iocx
- Plugins Meta‑Repo: https://github.com/iocx-dev/iocx-plugins
- Documentation: https://github.com/iocx-dev/iocx/tree/main/docs/specs
- PyPI Package: https://pypi.org/project/iocx/

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
- Crypto wallets (Ethereum / Bitcoin)

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

iocx/
│
├── examples/        # Sample files + generators
├── docs/            # Detector contracts, overlap suppression rules, and plugin authoring guidelines
├── tests/           # Unit, integration, fuzz, robustness, and performance tests
├── iocx
    ├── detectors/   # Regex-based IOC detectors
    ├── parsers/     # PE parsing, string extraction
    ├── plugins/     # Plugin API and registry
    ├── cli/         # Command-line interface

```

The engine is intentionally modular so components can be extended or replaced easily.

## Extending IOCX

See `docs/specs/` for:

- Detector contracts
- Overlap suppression rules
- Plugin authoring guidelines

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

## License

Licensed under the MIT License. See LICENSE for details.
