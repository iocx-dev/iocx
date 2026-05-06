# Security Policy

Thank you for your interest in the security of IOCX.
We take security seriously and aim to provide a trustworthy, minimal‑dependency tool for static IOC extraction across binaries, text, and logs.

This document describes our security posture, how we handle vulnerabilities, and how to report issues responsibly.

## Supported Versions

We currently support and maintain only the latest released version of IOCX.

| Version        | Status           |
|----------------|------------------|
| Latest release | Supported        |
| Older versions | Unsupported      |

Security fixes are applied exclusively to the most recent version.

## Security Posture

IOCX is designed with security and simplicity in mind. The tool processes untrusted input by design, so the architecture prioritises isolation, defensive parsing, and minimal attack surface.

### Minimal Runtime Dependencies

To reduce supply‑chain risk and minimise the attack surface, IOCX intentionally uses only a small set of well‑audited runtime dependencies. Each dependency is selected for deterministic behaviour, stability, and ecosystem maturity.

Current runtime dependencies:

- **pefile** — PE parsing and structural inspection
- **python‑magic** — file‑type detection via signature analysis
- **idna** — punycode decoding and Unicode domain normalisation (added in v0.7.2)

No additional libraries are required for core functionality. IOCX performs no dynamic execution, no network access, and no deserialisation of untrusted data.

### Automated Security Scanning

All commits and pull requests undergo automated security checks:

- pip‑audit — dependency vulnerability scanning
- Bandit — static analysis of Python code
- Pytest — full test suite execution

These checks run in CI to catch regressions early.

### Safe Handling of Untrusted Input

IOCX is designed to process potentially malicious files safely. To reduce risk:

- No dynamic code execution
- No deserialization of untrusted data
- No network access
- Strict parsing of binary formats
- Defensive exception handling in extractors and parsers
- No mutation of input files

### No Elevated Privileges Required

IOCX runs entirely in user space and does not require:

- root/admin privileges
- kernel extensions
- system‑level hooks

This reduces the impact of potential vulnerabilities.

## Threat Model (Scope & Limitations)

IOCX is a static extraction tool, not a sandbox or malware analysis framework.

The following are out of scope:

- Detecting or preventing active exploitation
- Executing or emulating malware
- Analysing runtime behaviour
- Guaranteeing correctness of third‑party plugins
- Protecting against malicious Python environments or compromised dependencies

Users should run IOCX in a controlled environment when analysing untrusted binaries.

Refer to the [threat model overview](/docs/security/threat-model.md) for Data Flow and STRIDE‑Oriented Threat Interaction Diagrams.

## Reporting a Vulnerability

We appreciate responsible disclosure and welcome reports from the community.

### How to report

Please email: security@malx.io

Include:

- A clear description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fixes or patches

We aim to acknowledge reports within 72 hours.

### Do Not Open Public GitHub Issues

Please avoid filing public issues for security problems. This protects users while we investigate and patch the issue.

## Vulnerability Disclosure Process

1. We receive and acknowledge your report.
2. We investigate and confirm the issue.
3. We develop and test a fix.
4. We release a patched version.
5. We publish a security advisory (if applicable).
6. We credit the reporter (unless anonymity is requested).

## Responsible Disclosure

We ask that reporters:

- Allow reasonable time for us to develop a fix
- Avoid exploiting the vulnerability beyond what is necessary for proof‑of‑concept
- Avoid accessing or modifying user data
- Refrain from public disclosure until a fix is released

We appreciate your help in keeping IOCX secure.
