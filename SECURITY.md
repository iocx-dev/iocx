# Security Policy

Thank you for your interest in the security of IOCX.
We take security seriously and aim to provide a trustworthy, minimal‑dependency tool for static IOC extraction across binaries, text, and logs.

This document explains how we handle security, how to report vulnerabilities, and what you can expect from us.

## Supported Versions

We currently support and maintain the latest release of this project.

| Version        | Supported        |
|----------------|------------------|
| Latest release | Active           |
| Older versions | Not supported    |

Security fixes are applied only to the most recent version.

## Security Posture

The project is designed with security and simplicity in mind.

### Minimal Runtime Dependencies

To reduce attack surface, the project intentionally uses only two runtime dependencies:

- pefile - PE parsing
- python-magic - file‑type detection

No additional libraries are required for core functionality.

### Automated Security Scanning

Every commit and pull request triggers automated checks:

- pip‑audit — dependency vulnerability scanning
- Bandit — static analysis of Python code
- Pytest — full test suite execution

These checks run in CI to prevent regressions and catch issues early.

### Safe Handling of Untrusted Input

The tool is designed to process potentially malicious files. To reduce risk:

- No dynamic code execution
- No deserialization of untrusted data
- No network access
- Strict parsing of binary formats
- Defensive exception handling in extractors and parsers

### No Elevated Privileges Required

The tool runs entirely in user space and does not require:

- root/admin privileges
- kernel extensions
- system‑level hooks

## Reporting a Vulnerability

If you discover a security issue, we appreciate responsible disclosure.

### How to report

Please email: security@malx.io

Include:

- Description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fixes

We aim to acknowledge reports within 72 hours.

### Please do not open public GitHub issues for security problems

This helps protect users while we investigate and patch the issue.

## Vulnerability Disclosure Process

1. We receive and acknowledge your report.
2. We investigate and confirm the issue.
3. We develop and test a fix.
4. We release a patched version.
5. We publish a security advisory (if applicable).
6. We credit the reporter.

## Responsible Disclosure

We ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Avoid exploiting the vulnerability beyond what is necessary for proof‑of‑concept
- Avoid accessing or modifying user data

We appreciate your help in keeping the project secure.
