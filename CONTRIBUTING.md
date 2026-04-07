# Contributing to IOCX

Thank you for your interest in contributing to IOCX. This project is part of the MalX Labs ecosystem — a collection of modern, developer‑friendly security tools focused on safe, scalable analysis.

We welcome improvements of all kinds: bug fixes, new extractors, static‑analysis enhancements, documentation updates, and thoughtful discussions. This guide explains how to contribute effectively while keeping the project consistent, deterministic, and maintainable.

## Project Philosophy

IOCX is intentionally:

- Minimal — very small dependency footprint
- Secure — safe handling of untrusted input
- Predictable — deterministic behaviour, no network access
- Extensible — new extractors and static‑analysis modules can be added cleanly

All contributions must align with these principles.

## Core vs Plugins

IOCX is built around a clear separation between core functionality and plugin‑based extensions. This boundary keeps the project focused and deterministic while allowing contributors to extend it safely.

### What Belongs in the Core

Core functionality is:

- derived entirely from the input file or text
- deterministic and reproducible
- universally useful to all users
- lightweight and dependency‑minimal
- fundamental to static IOC extraction and analysis

Examples:

- PE metadata extraction
- entropy scoring
- section/structure heuristics
- import/API heuristics
- phishing/lure string heuristics
- suspiciousness scoring
- structured output formats

If the information comes from the file itself, it belongs in the core.

### What Belongs in Plugins

Plugins are for functionality that is:

- optional
- environment‑specific
- user‑provided or user‑maintained
- based on external data
- not universally applicable
- likely to evolve independently of the core

Examples:

- offline reputation matching (local hash/domain/IP lists)
- organisation‑specific heuristics
- custom keyword or lure lists
- internal threat‑intel integrations

If the information comes from the user’s environment, it belongs in a plugin.

This separation ensures IOCX remains clean, predictable, and safe to run anywhere, while still enabling powerful extensions.

## How to Contribute

### Fix bugs

Open an issue or submit a PR with a clear description and reproduction steps.

### Add new IOC extractors

Regex‑based extractors live under `detectors/extractors/`.

Please include:

- a clear, well-scoped regex
- validation logic
- test cases
- test cases
- example inputs

### Improve PE parsing

Enhancements to metadata extraction, imports, sections, or resources are welcome — provided they remain deterministic and static.

### Add synthetic test samples

We do **not** accept real malware samples.
See the “Testing” section below.

### Improve documentation

Better examples, diagrams, or explanations are always appreciated.

### Contribution Process

1. Fork the repository

```bash
git clone https://github.com/iocx-dev/iocx.git

```

2. Create a feature branch

```bash
git checkout -b feature/my-improvement

```

3. Install locally

```bash
pip install -e .
```

4. Run tests

```bash
pytest
```

5. Run security checks

```bash
bandit -r iocx -lll
pip-audit --skip-editable
```

6. Open a Pull Request

When your changes are ready:

- Target the main branch
- Describe what you changed and why
- Link any related issues

CI will run automatically.

## Testing

IOCX is designed to be **safe to develop on any machine**.

### Do NOT:

- Upload or commit real malware
- Submit password‑protected malware archives
- Include malicious payloads or exploit code
- Add samples requiring execution to analyse

### Do:

- Use synthetic PE files
- Embed fake IOCs inside harmless executables
- Use benign Windows binaries for structural testing
- Use public test files like EICAR or GTUBE
- Add text files containing mixed IOCs

If unsure, open an issue before submitting.

### Tests

All new features should include tests.
Bug fixes should include a test that reproduces the issue.

Tests live in:
```plaintext
tests/
```

We use pytest.

## Adding New Extractors

```plaintext
iocx/detectors/extractors/
```

To add a new extractor:

- Create a new file in that directory
- Follow existing patterns
- Ensure it registers itself on import
- Add tests under tests/unit/extractors/

Extractors must be:

- deterministic
- side‑effect‑free
- safe for untrusted input

## Code Style

We keep the codebase clean and consistent.

- Format with Black
- Lint with Ruff (locally; CI does not enforce linting)
- Follow PEP8 and existing module structure

Run locally:

```bash
ruff check iocx
black iocx
```

## Security

If you discover a security issue, do not open a GitHub issue.

Follow the instructions in SECURITY.md.

## Code of Conduct

Be respectful, constructive, and supportive.
We aim for a collaborative, professional environment.

## License

By contributing, you agree that your contributions are licensed under the project's MIT License.

## Thank You

Your contributions help make IOCX better for everyone.
We’re grateful for your time, ideas, and expertise.
