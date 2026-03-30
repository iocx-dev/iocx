# IOCX — Static IOC Extraction Engine

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

## Extensibility

IOCX includes a lightweight plugin system that allows you to add custom detectors, parsers, and transformation rules.
Plugins can emit new IOC categories, override built-in behaviour, or integrate IOCX into larger analysis pipelines.

See the documentation for details on writing detectors and plugins.

## License

MIT License
