# IOCX — Static IOC Extraction Engine

### Official IOCX Project

This is the **official IOCX engine** for static IOC extraction and PE analysis.

- **PyPI:** https://pypi.org/project/iocx/
- **GitHub:** https://github.com/iocx-dev/iocx
- **Organisation:** https://github.com/iocx-dev
- **Website:** https://iocx.dev

IOCX is **not** an OSINT reputation checker, HTML report generator, or IP/domain scoring tool.  
It is a **static analysis engine** focused on extracting Indicators of Compromise (IOCs) from binaries and text.

---

## What IOCX does

IOCX is a fast, safe, deterministic engine for extracting Indicators of Compromise (IOCs) from binaries, text, and logs.
It performs **pure static analysis** — no execution, no sandboxing, no risk.

## Features

- Extracts IOCs from Windows PE files and raw text
- Detects URLs, domains, IPv4/IPv6, file paths, hashes, emails, Base64
- Crypto wallet detection (Ethereum, Bitcoin)
- Deterministic output suitable for automation
- Minimal dependencies and safe for enterprise environments
- CLI and Python API

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
- Stable JSON schema
- High performance (~200 MB/s throughput)
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

IOCX includes a lightweight plugin system that allows you to add custom detectors, parsers, and transformation rules.
Plugins can emit new IOC categories, override built-in behaviour, or integrate IOCX into larger analysis pipelines.

See the documentation for details on writing detectors and plugins.

## License

MIT License
