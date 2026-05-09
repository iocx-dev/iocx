# IOCX
### **Deterministic, Zero‑Risk IOC Extraction for Modern Security Pipelines**

<p align="center">
  <img src="https://iocx.dev/assets/iocx_demo.gif" width="720" alt="IOCX Demo">
</p>

<p align="center"><sub>Static IOC extraction from a PE file using the IOCX CLI</sub></p>

<p align="center">
  <a href="https://pypi.org/project/iocx/"><img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white"></a>
  <img src="https://img.shields.io/badge/tests-734_passed-brightgreen">
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen">
  <img src="https://img.shields.io/badge/python-3.12-blue">
  <a href="https://github.com/iocx-dev/iocx/actions"><img src="https://img.shields.io/github/actions/workflow/status/iocx-dev/iocx/ci.yml?label=build"></a>
  <a href="https://github.com/iocx-dev/iocx/blob/main/LICENSE"><img src="https://img.shields.io/github/license/iocx-dev/iocx"></a>
</p>

# Official IOCX Project

This is the original IOCX engine for deterministic static IOC extraction and PE analysis.
Any other repositories using the name "iocx" are **not affiliated** with this project.

**Official links:**

- PyPI: [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)
- Github: [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)
- Website: [https://iocx.dev/](https://iocx.dev/)

---

# Why IOCX Matters

Modern malware is **adversarial by default** — malformed, evasive, and engineered to break naive extractors.

- Regex‑only tools fail under real adversarial pressure
- Sandboxes are unsafe and unusable in CI/CD
- Binary‑unaware scripts collapse under malformed PEs

**IOCX is built for the world we actually live in.**

---

# The IOCX Engine

**IOCX is the official static IOC extraction engine** — a deterministic, binary‑aware system built for DFIR, SOC automation, CI/CD security, and large‑scale threat‑intel pipelines.

Unlike regex‑only extractors or sandbox‑dependent tools, IOCX performs:

- **pure static analysis**
- **zero execution risk**
- **stable, deterministic output**
- **adversarial‑tested heuristics**

It is a core component of the MalX Labs ecosystem for scalable, modern threat analysis.

---

# Try IOCX in 10 Seconds

```bash
echo "http://malicious.example" | iocx -
```

Or scan a PE file safely:

```bash
iocx suspicious.exe -a deep
```

---

# Why IOCX Exists

Security teams face three persistent problems:

1. **Regex‑only extractors break under adversarial input**
2. **Sandboxing is unsafe, slow, and unsuitable for CI/CD**
3. **Most tools cannot parse binaries or reason about PE structure**

IOCX solves all three with a **deterministic, static‑only engine** designed for automation, safety, and scale.

---

# What IOCX *Is Not*

IOCX is intentionally **not**:

- a sandbox
- a behavioural analysis tool
- an emulator
- an enrichment engine

It never executes untrusted code.
It never performs dynamic analysis.
It is **static‑only by design** — for safety, determinism, and CI/CD compatibility.

---

# Design Philosophy

IOCX is engineered for the realities of modern malware, not the assumptions of legacy tools.

### **1. Determinism over ambiguity**
Stable, reproducible output — no randomness, no volatility.

### **2. Static over dynamic**
Execution is unsafe. Static analysis is predictable, scalable, and CI‑friendly.

### **3. Adversarial‑first engineering**
Malformed PEs, corrupted RVAs, hostile strings — IOCX treats them as normal input.

### **4. Schema stability as a contract**
Downstream systems should never break on upgrade.

### **5. Performance without compromise**
150–300 MB/s on raw text.
6–15 MB/s on typical PEs.
Predictable even under worst‑case adversarial load.

---

# What Makes IOCX Different

| Capability | **IOCX** | Typical IOC Extractors | Sandbox / Dynamic Tools |
|-----------|-----------|------------------------|--------------------------|
| **Safety** | Zero‑execution, static‑only | Regex‑only, no binary safety | Executes untrusted code (high‑risk) |
| **Determinism** | Fully deterministic output | Non‑deterministic under noise | Non‑deterministic by design |
| **Binary Awareness** | Full PE parsing, heuristics | No binary support | Yes, but unsafe + slow |
| **Adversarial Resilience** | Tested against malformed PEs, hostile strings | Easily bypassed | Often crashes or misclassifies |
| **Performance** | 150–300 MB/s (text), 6–15 MB/s (PE) | Highly variable | Extremely slow |
| **CI/CD Friendly** | Yes — safe, deterministic, fast | Partial | No — unsafe for pipelines |
| **Schema Stability** | Guaranteed | Rare | None |

**In short:** IOCX is built for *real adversarial reality*, not idealized input.

---

# Use Cases

### CI/CD & DevSecOps
- Scan binaries before release
- Detect accidental URLs, IPs, or secrets in builds
- Enforce security gates with zero execution risk

### SOC & Incident Response
- Extract indicators from alerts or analyst clipboard text
- Safely inspect malware samples without execution
- Normalize IOCs into structured JSON

### Threat Intelligence
- Process feeds at scale
- Parse unstructured reports
- Build enrichment pipelines on deterministic output

### Automation & Scripting
- Pipe logs or artifacts through IOCX
- Use the Python API for ETL or batch workflows
- Extend with custom detectors

---

# Performance Profiles

### **1. Raw IOC Extraction (Text, Logs, Buffers)**
**150–300 MB/s** sustained throughput
Fast path — no PE parsing.

| Detector | 1 MB Time | Throughput |
|----------|-----------|------------|
| Crypto | 0.0037 s | ~270 MB/s |
| Filepaths | 0.0040 s | ~250 MB/s |
| IP | 0.0064 s | ~156 MB/s |
| Domains | 0.0033 s | ~300 MB/s |

---

### **2. Typical PE Files (~39 KB)**
- **0.0132 s** (typical)
- **0.0153 s** (with heuristics)
- **6–15 MB/s** throughput

---

### **3. Adversarial Dense PE (1.5 MB)**
- **0.1977 s**
- **~7.6 MB/s** throughput
- Triggers TLS anomalies, structural anomalies, anti‑debug patterns

---

### **4. Full Engine (Non‑PE)**
- **1 MB:** 0.0411 s

---

# Version Highlights

<details>
<summary><strong>Show Version History</strong></summary>
<br>

### **v0.7.2 — Dependency Fix**
- Added missing `idna` dependency
- No behavioural or schema changes

---

### **v0.7.1 — Adversarial Heuristics Expansion & Parser Hardening**
- Six new PE heuristics
- Expanded adversarial PE corpus
- Hardened domain/URL/crypto/hash extractors
- Deterministic snapshot‑validated output

---

### **v0.7.0 — Deterministic Heuristics & Adversarial Testing Foundation**
- Deterministic heuristics
- Layer‑3 adversarial samples
- Snapshot‑contract tests
- Rich Header crash fix

---

### **v0.6.0 — Stable Output Schema & Deterministic Metadata**
- Fully stable JSON schema
- Normalised PE metadata
- Formalised analysis levels

---

### **v0.5.0 — Analysis Levels, PE Section Analysis, Obfuscation Hints**
- New analysis‑level system
- PE structural analysis
- Obfuscation heuristics

---

### **v0.4.0 — Plugin Architecture**
- Plugin‑ready rule engine
- Unified detection flow

---

### **v0.3.0 — Crypto IOC Detection**
- Ethereum & Bitcoin wallet detection

---

### **v0.2.0 — High‑Reliability IP Detection**
- Major IPv4/IPv6 improvements

</details>

---

# Quickstart

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

### Enable PE analysis
```bash
iocx suspicious.exe -a
```

### Python API
```python
from iocx.engine import Engine

engine = Engine()
results = engine.extract("suspicious.exe")
print(results)
```

---

# Example Output

<details>
<summary><strong>Show Example JSON Output</strong></summary>

```json
{$ iocx chaos_corpus.json
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
    "base64": [],
    "crypto.btc": [],
    "crypto.eth": []
  },
  "metadata": {}
}

```

</details>
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

---

# Architecture

```
iocx/
├── examples/
├── docs/
├── tests/
└── iocx
    ├── detectors/
    ├── parsers/
    ├── plugins/
    ├── cli/
    └── analysis/
```

---

# Plugin Ecosystem & Extensibility

IOCX is designed to be extended safely and predictably.
Plugins are **first‑class citizens**, validated by the same deterministic snapshot tests as the core engine.

You can build:

- custom IOC detectors
- custom regex rules
- binary‑aware plugins
- internal heuristics
- pipeline‑specific extractors

See:

- `docs/specs/overlap-suppression.md`
- `docs/specs/plugin-authoring-guidelines.md`

---

# Ecosystem Overview

IOCX is more than a single binary — it’s a modular ecosystem:

- **Core Engine** — deterministic IOC extraction + PE analysis
- **Plugin System** — custom detectors and analysis modules
- **Adversarial Corpus** — malformed PEs, hostile strings, fuzz samples
- **Snapshot Testing Framework** — ensures deterministic output
- **Performance Benchmarks** — enforced in CI
- **Documentation Suite** — specs, contracts, and plugin guides

---

# Who Uses IOCX?

IOCX is used across:

- DFIR teams
- SOC automation pipelines
- CI/CD security gates
- Threat‑intel platforms
- Malware research labs
- Security engineering teams

Anywhere indicators need to be extracted **safely**, **deterministically**, and **at scale**, IOCX fits.

---

# Safe Testing (No Malware Required)

All test samples are:

- Synthetic
- Benign
- Publicly safe (EICAR, GTUBE)
- Designed to avoid accidental malware handling

---

# Performance Guarantees

IOCX enforces strict performance thresholds in CI to ensure:

- No regex backtracking stalls
- No pathological slowdowns
- Stable performance across releases

See:

- `docs/performance.md`

---

# Project Identity & Naming

The name **IOCX** refers exclusively to the official engine published on:

- PyPI: [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)
- GitHub: [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)

### Not allowed
- Repositories named `iocx`
- Tools named “iocx” not part of this project
- Implying affiliation without permission

### Allowed
- `iocx-<plugin>`
- `iocx-extension-<name>`
- `iocx-detector-<feature>`

---

# Official IOCX Repositories

- Core Engine: [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)
- Plugins Meta‑Repo: [https://github.com/iocx-dev/iocx-plugins](https://github.com/iocx-dev/iocx-plugins)
- Documentation: [https://github.com/iocx-dev/iocx/tree/main/docs/specs](https://github.com/iocx-dev/iocx/tree/main/docs/specs)
- PyPI Package: [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)

---

# Roadmap

### **Q2 2026**
- Plugin sandboxing for untrusted detectors
- Extended PE heuristics (delay‑load, CFG, reloc anomalies)
- Domain‑specific suppression rules (OSINT, DFIR, TI)

### **Q3 2026**
- ELF + Mach‑O metadata extraction
- Multi‑artifact batch mode
- IOCX‑server (stateless HTTP extraction API)

### **Q4 2026**
- YARA‑compatible output mode
- IOCX‑cloud corpus for adversarial samples
- Threat‑intel enrichment hooks (opt‑in)

### **2027+**
- Full binary‑agnostic static analysis layer
- Cross‑platform plugin marketplace
- Multi‑language bindings (Rust, Go, Node)

---

# Contributing

We welcome:

- New detectors
- Parser improvements
- Documentation updates
- Synthetic adversarial samples

See `CONTRIBUTING.md` for guidelines.

---

# Security

If you discover a security issue, **do not open a GitHub issue**.
Follow the instructions in `SECURITY.md`.

---

# License

MPL‑2.0 License — see `LICENSE`.
