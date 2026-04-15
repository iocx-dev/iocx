# Official IOCX Project

This is the **original IOCX engine** for static IOC extraction and PE analysis.
Any other repositories using the name "iocx" are **not affiliated** with this project.

- PyPI: [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)
- Github: [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)
- Website: [https://iocx.dev/](https://iocx.dev/)

<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-633_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/iocx-dev/iocx/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/iocx-dev/iocx" alt="License">
  </a>
  <a href="https://github.com/iocx-dev/iocx/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/iocx-dev/iocx/ci.yml?label=build" alt="Build Status">
  </a>
  <img src="https://img.shields.io/badge/performance-28MB/s_engine_|_450MB/s_peak_|_0.0004s_path-brightgreen" alt="Performance Summary">
</p>

<p align="center">
  <img src="https://iocx.dev/assets/iocx_demo.gif" alt="IOCX Demo" width="720">
  <sub>Static IOC extraction from a PE file using the IOCX CLI</sub>
</p>

# IOCX — Static IOC Extraction for Binaries, Text, and Artifacts

**Fast, safe, deterministic IOC extraction for DFIR, SOC automation, and large-scale threat analysis.**

IOCX is a lightweight, extensible engine for extracting Indicators of Compromise (IOCs) and structural metadata using **pure static analysis**. No execution. No sandboxing. No risk.

Built for:

- DFIR workflows
- SOC automation
- Threat-intel pipelines
- CI/CD security checks
- Large‑scale batch processing

IOCX is a core component of the MalX Labs ecosystem for scalable, modern threat‑analysis tooling.

## Why IOCX?

IOCX is designed for environments where **safety, determinism, and automation** matter. Unlike extractors that operate only on raw text, IOCX includes:

- Binary‑aware static analysis
- A plugin-friendly rule system
- A stable JSON schema suitable for pipelines and long-term integrations

### Key advantages

- **Static‑only design** — never executes untrusted code
- **Binary parsing** — PE-aware extraction with section analysis, entropy, and obfuscation hints
- **Analysis level** — basic, deep, and full for performance-tuned workflows
- **Deterministic behaviour** — stable output and predictable performance
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

### v0.6.0 — Stable Output Schema, Deterministic PE Metadata, Contract‑Safe Analysis Levels

- Introduced a fully stable JSON schema across all analysis levels
- Added strict structural guarantees for `iocs`, `metadata`, and `analysis` blocks
- Normalised PE metadata fields for deterministic output (headers, TLS, optional header, signatures)
- Ensured **all IOC categories always exist** (empty arrays when no matches)
- Formalised analysis‑level behaviour:
  - core behaviour → no analysis block
  - basic → section layout + entropy
  - deep → adds obfuscation heuristics
  - full → adds extended metadata summaries
- Added **snapshot‑contract tests** to prevent schema drift across releases
- Improved PE parser consistency for imports, resources, and section metadata
- Strengthened safety guarantees for CI/CD and large‑scale automation pipelines

This release establishes the long‑term schema contract that downstream tools can rely on.

### v0.5.0 — Analysis Levels, PE Section Analysis, Obfuscation Hints

- New analysis‑level system: basic, deep (default), and full (future‑ready)
- PE structural analysis: section layout, raw/virtual sizes, entropy
- Obfuscation heuristics: abnormal section patterns, virtual‑only sections, entropy anomalies
- Extended analysis stub for future packer/TLS/anti‑debug modules
- Clean, stable JSON schema with optional analysis block
- No‑flag mode remains fast and minimal for pipeline use

### v0.4.0 — Plugin Architecture, Custom Detectors, Cleaner Internals

- Introduced the plugin‑ready rule engine, enabling custom IOC detectors and parsers
- Unified internal detection flow under a consistent, extensible interface
- Added support for user‑defined regex detectors and lightweight parsing modules
- Improved separation between core engine, detectors, and output formatting
- Reduced coupling across modules to support long‑term extensibility
- Maintained the same fast, deterministic performance profile

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

- URLs
- Domains
- IPv4 / IPv6 addresses
- File paths (Windows, Linux, UNC, env-vars)
- Hashes (MD5 / SHA1 / SHA256 / SHA512 / Generic Hex)
- Email addresses
- Base64 strings
- Crypto wallets (Ethereum / Bitcoin)

### Binary-aware Static Analysis

- Windows PE files (`.exe`, `.dll`)
- Extracted strings from binaries
- Imports, sections, resources, metadata
- **Analysis levels:**
  - `basic` - section layout + entropy
  - `deep` - adds obfuscation heuristics
  - `full` - extended analysis stub (*future-ready*)

### Performance & Caching

- Fast startup and throughput
- Optional caching for repeated scans
- Suitable for CI/CD and large batch workflows

### Developer‑Friendly

- Clean, stable JSON output
- CLI + Python API
- Modular, extensible rule system
- Minimal dependency footprint

### Security‑First

- Zero malware execution
- Safe for untrusted input
- Deterministic behaviour for pipelines

### Why Static Only?

Static analysis ensures **safety**, **determinism**, and **CI‑friendly operation**. No sandboxing, no execution, and no risk of triggering malware behaviour.

## Output Schema (v0.6.0)

IOCX v0.6.0 defines a stable, deterministic JSON schema designed for DFIR, SOC automation, and threat‑intel pipelines. The schema is intentionally simple, predictable, and safe for long‑term integrations.

The top‑level structure contains three blocks:

- `iocs` — extracted indicators
- `metadata` — structural information about the artifact
- `analysis` — optional deeper inspection depending on analysis level

This structure is identical across all input types, with PE‑specific fields populated only when applicable.

### IOC Categories

The `iocs` block always contains the same keys, regardless of analysis level:

- `urls`
- `domains`
- `ips`
- `hashes`
- `emails`
- `filepaths`
- `base64`
- `crypto.btc`
- `crypto.eth`

Each category is always an array. Empty categories are returned as empty arrays to ensure predictable downstream parsing.

### Metadata Categories

The metadata block contains structural information about the file. For PE files, this includes:

- Imports and import details
- Sections
- Resources and resource strings
- TLS directory
- Header and optional header
- Rich header
- Signatures

These fields are always present, even when empty. Metadata is **independent of analysis level** and is always returned in full.

### Analysis Levels

The `analysis` block is the only part of the schema that changes based on the selected analysis level.

- **basic** — section layout + entropy
- **deep** — adds obfuscation heuristics
- **full** — adds extended metadata summaries

This tiered design allows users to trade off performance vs. depth without changing their downstream parsing logic.

### Deterministic Output

IOCX v0.6.0 guarantees:

- Stable keys
- Stable types
- No volatile values in minimal modes
- Deterministic behaviour across runs and platforms

This makes IOCX safe for SIEM/SOAR ingestion, CI/CD pipelines, and large‑scale batch processing.

### Schema stability

IOCX guarantees a stable JSON schema, not a guaranteed ordering of keys within objects. JSON objects are defined as unordered maps, so consumers should rely on field presence and structure rather than positional ordering. All fields, types, and structural relationships remain consistent across versions, even if internal key order changes.

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

### Enable PE analysis
```bash
iocx suspicious.exe -a
```
Or choose a specific level:
```bash
iocx suspicious.exe -a basic
iocx suspicious.exe -a deep
iocx suspicious.exe -a full
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
    "urls": [],
    "domains": [],
    "ips": [],
    "hashes": [],
    "emails": [],
    "filepaths": [
      "C:\\Windows\\System32\\cmd.exe",
      "D:\\Temp\\payload.bin",
      "E:/Users/Bob/AppData/Roaming/evil.dll",
      "F:\\Program Files\\SomeApp\\bin\\run.exe",
      "C:\\Users\\Alice\\Desktop\\notes.txt",
      "Z:\\Archive\\2024\\logs\\system.log",
      "\\\\SERVER01\\share\\dropper.exe",
      "\\\\192.168.1.44\\c$\\Windows\\Temp\\run.ps1",
      "\\\\FILESRV\\public\\docs\\report.pdf",
      "\\\\NAS01\\data\\backups\\2024\\config.json",
      "/usr/bin/python3.11",
      "/etc/passwd",
      "/var/lib/docker/overlay2/abc123/config.v2.json",
      "/tmp/x1/x2/x3/x4/x5/script.sh",
      "/opt/tools/bin/runner",
      "/home/alice/.config/evil.sh",
      ".\\payload.exe",
      "..\\lib\\config.json",
      "./run.sh",
      "../bin/loader.so",
      ".\\scripts\\install.ps1",
      "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
      "%TEMP%\\payload.exe",
      "%USERPROFILE%\\Downloads\\file.txt",
      "$HOME/.config/evil.sh",
      "$HOME/bin/run.sh",
      "$TMPDIR/cache/tmp123.bin",
      "C:\\Windows\\Temp\\payload.bin",
      "/home/alice/.config/evil"
    ],
    "base64": [],
    "crypto.btc": [],
    "crypto.eth": []
  },
  "metadata": {
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
      ".rsrc",
      ".reloc"
    ],
    "resource_strings": [
      "C:\\Windows\\System32\\cmd.exe",
      "\\\\SERVER01\\share\\dropper.exe",
      "/home/alice/.config/evil.sh@%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"
    ]
  },
  "analysis": {
    "sections": [
      {
        "name": ".text",
        "raw_size": 7168,
        "virtual_size": 6712,
        "characteristics": 1610612832,
        "entropy": 5.790750971742716
      },
      {
        "name": ".data",
        "raw_size": 512,
        "virtual_size": 464,
        "characteristics": 3221225536,
        "entropy": 2.094202310841767
      },
      {
        "name": ".rdata",
        "raw_size": 3584,
        "virtual_size": 3408,
        "characteristics": 1073741888,
        "entropy": 4.545752258688727
      },
      {
        "name": ".pdata",
        "raw_size": 1024,
        "virtual_size": 540,
        "characteristics": 1073741888,
        "entropy": 2.327719716055491
      },
      {
        "name": ".xdata",
        "raw_size": 512,
        "virtual_size": 488,
        "characteristics": 1073741888,
        "entropy": 4.1370410751038245
      },
      {
        "name": ".bss",
        "raw_size": 0,
        "virtual_size": 384,
        "characteristics": 3221225600,
        "entropy": 0.0
      },
      {
        "name": ".idata",
        "raw_size": 1536,
        "virtual_size": 1472,
        "characteristics": 3221225536,
        "entropy": 3.7542599473501452
      },
      {
        "name": ".CRT",
        "raw_size": 512,
        "virtual_size": 96,
        "characteristics": 3221225536,
        "entropy": 0.2718922950073886
      },
      {
        "name": ".tls",
        "raw_size": 512,
        "virtual_size": 16,
        "characteristics": 3221225536,
        "entropy": 0.0
      },
      {
        "name": ".rsrc",
        "raw_size": 512,
        "virtual_size": 416,
        "characteristics": 1073741888,
        "entropy": 2.6481096709923975
      },
      {
        "name": ".reloc",
        "raw_size": 512,
        "virtual_size": 188,
        "characteristics": 1107296320,
        "entropy": 2.2248162937403557
      }
    ],
    "obfuscation": [
      {
        "value": "abnormal_section_layout_virtual_only",
        "start": 0,
        "end": 0,
        "category": "obfuscation_hint",
        "metadata": {
          "section": ".bss",
          "raw_size": 0,
          "virtual_size": 384
        }
      }
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
    ├── analysis/    # PE static-analysis modules

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


*The IOCX name and project identity refer exclusively to the IOCX engine maintained under the iocx-dev organisation*
