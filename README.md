# malx‑ioc‑extractor

Static IOC extraction for binaries, text, and artifacts — fast, safe, open‑source.

malx‑ioc‑extractor is a lightweight, extensible engine for extracting Indicators of Compromise (IOCs) from files and text using static analysis only. No execution. No sandboxing. No risk.

It’s designed to be:

    Safe — never executes untrusted code

    Fast — built for automation and pipelines

    Extensible — plug in your own regexes, parsers, and rules

    Developer‑friendly — clean API, CLI, and examples

    Open‑source — the extraction engine is free; enrichment lives in the MalX cloud platform

This project is the foundation of the MalX Labs ecosystem for scalable, modern threat‑analysis tooling.
⭐ Features

    Extracts IOCs from:

        Windows PE files (.exe, .dll)

        Raw text

        Strings extracted from binaries

    Detects:

        URLs

        Domains

        IPv4/IPv6 addresses

        File paths

        Registry keys

        Hashes (MD5/SHA1/SHA256)

        Emails

    Static PE parsing:

        Imports

        Sections

        Resources

        Metadata

    Clean JSON output

    CLI + Python library

    Extensible rule system

    Zero malware execution

🚀 Quickstart
Install
bash

pip install malx-ioc-extractor

Extract IOCs from a file
bash

malx-ioc-extract suspicious.exe

Extract from text
bash

echo "Contact http://bad.example.com" | malx-ioc-extract -

Python usage
python

from malx_ioc_extractor import extract_iocs

results = extract_iocs("suspicious.exe")
print(results)

📦 Output Example
json

{
  "file": "suspicious.exe",
  "iocs": {
    "urls": ["http://malicious.example.com"],
    "domains": ["malicious.example.com"],
    "ips": ["45.77.12.34"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
  },
  "metadata": {
    "file_type": "PE32 executable",
    "imports": ["kernel32.dll", "ws2_32.dll"],
    "sections": [".text", ".rdata", ".data"]
  }
}

🧩 Architecture
Code

malx-ioc-extractor/
│
├── extractors/      # Regex-based IOC detectors
├── parsers/         # PE parsing, string extraction
├── validators/      # Normalisation + dedupe
├── cli/             # Command-line interface
├── tests/           # Unit tests
└── examples/        # Sample files + usage demos

The design is intentionally modular so you can extend or replace components easily.
🔧 Extending the Engine

You can add your own:

    Regex detectors

    YARA rules

    File parsers

    Normalisation logic

Example: adding a custom regex rule:
python

from malx_ioc_extractor import register_pattern

register_pattern("crypto_wallet", r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}")

🧪 Safe Testing (No Malware Required)

All PoCs in this repo use:

    Synthetic PE files

    Benign executables

    Fake embedded IOCs

    Public test files (EICAR, GTUBE)

This keeps development safe and accessible.
🌐 MalX Cloud Enrichment (Optional)

The open‑source extractor is local‑only and static‑only.

For enrichment (WHOIS, DNS, threat feeds, scoring), use the MalX Cloud API:

    Reputation lookups

    Threat‑intel correlation

    IOC scoring

    Automated reporting

Coming soon.
🤝 Contributing

We welcome:

    New IOC detectors

    Parser improvements

    Bug reports

    Documentation fixes

    Synthetic test samples

See CONTRIBUTING.md for guidelines.
📚 Related Projects (MalX Labs)

    malx-core — foundational primitives

    malx-utils — shared utilities

    malx-sandbox — dynamic analysis environment

    malx-forge — adversarial payload tooling

    malx-archive — research + PoCs

📄 License

MIT License — free to use, modify, and integrate.
