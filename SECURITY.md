# Security Policy

Thank you for your interest in the security of IOCX.
We take security seriously and aim to provide a trustworthy, minimal‑dependency tool for static IOC extraction across binaries, text, and logs.

This document describes our security posture, how we handle vulnerabilities, and how to report issues responsibly.

---

## Supported Versions

We currently support and maintain only the latest released version of IOCX.

| Version          | Status        |
|------------------|---------------|
| Latest release   | Supported     |
| Older versions   | Unsupported   |

Security fixes are applied exclusively to the most recent version.
Security guarantees apply only to the official IOCX core.
Third-party plugins may introduce additional risk.

---

## Security Posture

IOCX is designed with security and simplicity in mind. The tool processes untrusted input by design, so the architecture prioritises isolation, defensive parsing, and minimal attack surface.

### Minimal Runtime Dependencies

To reduce supply‑chain risk and minimise the attack surface, IOCX intentionally uses only a small set of well‑audited runtime dependencies. Each dependency is selected for deterministic behaviour, stability, and ecosystem maturity.

Current runtime dependencies:

- **pefile** — PE parsing and structural inspection
- **python‑magic** — file‑type detection via signature analysis
- **idna** — punycode decoding and Unicode domain normalisation

No additional libraries are required for core functionality. IOCX performs:

- no dynamic execution
- no network access
- no deserialisation of untrusted data

### Automated Security Scanning

All commits and pull requests undergo automated security checks:

- **pip‑audit** — dependency vulnerability scanning
- **Bandit** — static analysis of Python code
- **Pytest** — full test suite execution

These checks run in CI to catch regressions early.

### Safe Handling of Untrusted Input

IOCX is designed to process potentially malicious files safely. To reduce risk:

- no dynamic code execution
- no deserialization of untrusted data
- no network access
- strict parsing of binary formats
- defensive exception handling in extractors and parsers
- no mutation of input files

### No Elevated Privileges Required

IOCX runs entirely in user space and does not require:

- root/admin privileges
- kernel extensions
- system‑level hooks

This reduces the impact of potential vulnerabilities.

---

## Threat Model (Scope & Limitations)

IOCX is a static extraction tool, not a sandbox or malware analysis framework.

The following are out of scope:

- detecting or preventing active exploitation
- executing or emulating malware
- analysing runtime behaviour
- guaranteeing correctness of third‑party plugins
- protecting against malicious Python environments or compromised dependencies

Users should run IOCX in a controlled environment when analysing untrusted binaries.

Refer to the threat‑model documentation for data‑flow diagrams and STRIDE‑oriented analysis.

---

## Reporting a Vulnerability

We appreciate responsible disclosure and welcome reports from the community.

### How to report

Please email: **security@malx.io**

Include:

- a clear description of the issue
- steps to reproduce
- potential impact
- any suggested fixes or patches

We aim to acknowledge reports within **72 hours**.

### Do Not Open Public GitHub Issues

Please avoid filing public issues for security problems.
This protects users while we investigate and patch the issue.

---

## Vulnerability Disclosure Process

1. We receive and acknowledge your report.
2. We investigate and confirm the issue.
3. We develop and test a fix.
4. We release a patched version.
5. We publish a security advisory (if applicable).
6. We credit the reporter (unless anonymity is requested).

---

## Responsible Disclosure

We ask that reporters:

- allow reasonable time for us to develop a fix
- avoid exploiting the vulnerability beyond what is necessary for proof‑of‑concept
- avoid accessing or modifying user data
- refrain from public disclosure until a fix is released

We appreciate your help in keeping IOCX secure.

---

## Commercial Customers

Commercial licensees may receive:

- priority security response
- extended support windows
- advance notification of critical issues
- access to patched builds before public release

For enterprise security inquiries, contact: **security@malx.io**

---

## Trademark Notice

“IOCX” is a trademark of Peter Weaver.
See TRADEMARK_POLICY.md for permitted and restricted use of the IOCX name.

IOCX is licensed under the Mozilla Public License 2.0 (MPL-2.0).
