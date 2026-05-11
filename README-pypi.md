# **IOCX — Deterministic, Zero‑Risk IOC Extraction for Modern Security Pipelines**
### Official IOCX Project

**IOCX** is a high‑performance, deterministic static analysis engine for extracting Indicators of Compromise (IOCs) from binaries and text.
It exists for one reason: **to provide a fast, safe, predictable IOC extractor that DFIR teams and automation pipelines can trust.**

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

## Version highlights (v0.7.3)

- Major hardening of all PE structural validators
- Deterministic, snapshot‑stable output across malformed binaries
- Stronger section, entrypoint, RVA‑graph, TLS, and signature checks
- Corrected RVA→file‑offset mapping for overlay detection
- Improved entropy analysis with clearer, conservative signals
- Cleaner, consistent `ReasonCodes` across the engine
- Expanded structural + heuristic test coverage

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
