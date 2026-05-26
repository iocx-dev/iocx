# **IOCX — Deterministic, Zero‑Risk IOC Extraction for Modern Security Pipelines**
### Official IOCX Project

**IOCX** is a deterministic, high‑performance static analysis engine for extracting high-signal Indicators of Compromise (IOCs) from binaries, text, and logs.
It’s built for DFIR teams, SOC automation, CI/CD pipelines, and large‑scale threat‑intel ingestion.

**Why it matters:** IOCX guarantees snapshot‑stable output, zero‑risk static analysis, and predictable performance even under adversarial input — something regex‑only extractors simply can’t provide.

- **PyPI:** [https://pypi.org/project/iocx/](https://pypi.org/project/iocx/)
- **GitHub:** [https://github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx)
- **Website:** [https://iocx.dev](https://iocx.dev)

IOCX is **not** an OSINT reputation checker or scoring tool.
It is a **binary‑aware IOC engine** built for DFIR, SOC automation, CI/CD, and threat‑intel ingestion.

---

## Why IOCX Exists

Most IOC extractors are:

- regex‑only
- non‑deterministic
- slow under adversarial input
- unaware of binary structure
- unstable across versions

**IOCX fixes all of that.**

It provides:

- **snapshot‑stable output**
- **deterministic PE metadata extraction**
- **binary‑aware heuristics**
- **strict performance guarantees**
- **a stable JSON schema**
- **safe, static‑only analysis**

If you need predictable, automatable IOC extraction — IOCX is built for you.

---

## Version highlights (v0.7.4)

- Full **Load Config Directory** parsing and validation
- Extended Optional Header metadata for downstream heuristics
- Structural anomaly heuristics (GuardCF, unmapped cookie, SEH issues)
- Faster, more resilient PE Analysis
- Raw IOC extraction remains world-class
- Zero regressions across all workloads

---

## **Performance**

- **150–300 MB/s on raw text**
- **6–15 MB/s on typical PEs**
- **Predictable** even under worst‑case adversarial load.

---

## Features

- Extracts IOCs from PE files and raw text
- Detects domains, URLs, IPv4/IPv6, file paths, hashes, emails, Base64
- Crypto wallet detection (BTC, ETH)
- Deterministic, snapshot‑stable JSON output
- Multi‑level analysis depth (`basic` → `full`)
- Binary‑aware static analysis (entropy, sections, imports, TLS, signatures)
- Lightweight plugin system
- CLI + Python API

---

## Install

```bash
pip install iocx
```

---

## CLI

```bash
iocx suspicious.exe
```

```bash
echo "Visit http://bad.example.com" | iocx -
```

---

## Python API

```python
from iocx.engine import Engine

engine = Engine()
results = engine.extract("suspicious.exe")
print(results)
```

---

## Project Identity

The name **IOCX** refers exclusively to this project and the repositories under **iocx-dev**.
Third‑party tools must not present themselves as the IOCX engine.

Community integrations should use names like:

- `iocx-<plugin>`
- `iocx-extension-<feature>`

---

## License

**MPL‑2.0**
