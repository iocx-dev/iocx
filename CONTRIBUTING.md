# Contributing to IOCX

Thank you for your interest in contributing to IOCX.
IOCX is part of the MalX Labs ecosystem — a family of modern, deterministic, developer‑friendly security tools designed for safe analysis of untrusted data.

We welcome contributions of all kinds: bug fixes, static‑analysis improvements, new extractors, documentation updates, and thoughtful design discussions.
This guide explains how to contribute effectively while keeping IOCX predictable, secure, and maintainable.

---

## Project Philosophy

IOCX is intentionally:

- **Minimal** — extremely small dependency footprint
- **Secure** — safe handling of untrusted input
- **Deterministic** — no network access, no non‑deterministic behaviour
- **Extensible** — new static‑analysis modules can be added cleanly

All contributions must align with these principles.

---

## Core vs Plugins

IOCX has a strict boundary between **core functionality** and **plugin‑based extensions**.
This keeps the core predictable and universally safe while allowing users to extend IOCX for their own environments.

### What Belongs in the Core

Core functionality must be:

- derived entirely from the input file or text
- deterministic and reproducible
- universally useful
- lightweight and dependency‑minimal
- fundamental to static IOC extraction

Examples:

- PE metadata extraction
- entropy calculations
- section/structure heuristics
- import/API heuristics
- phishing/lure string heuristics
- suspiciousness scoring
- structured output formats

If the information comes from the file itself, it belongs in the core.

### What Belongs in Plugins

Plugins are for functionality that is:

- optional or environment‑specific
- based on external data
- organisation‑specific
- user‑maintained
- likely to evolve independently

Examples:

- offline reputation matching (local hash/domain/IP lists)
- organisation‑specific heuristics
- custom lure or keyword lists
- internal threat‑intel integrations

If the information comes from the user’s environment, it belongs in a plugin.

This separation keeps IOCX clean, predictable, and safe to run anywhere.

---

## How to Contribute

### Fix bugs

Open an issue or submit a PR with:

- a clear description
- reproduction steps
- expected vs actual behaviour

### Add new IOC extractors

Regex‑based extractors live under:

```
iocx/detectors/extractors/
```

Please include:

- a clear, well‑scoped regex
- validation logic
- test cases
- example inputs

Extractors must be:

- deterministic
- side‑effect‑free
- safe for untrusted input

### Improve PE parsing

Enhancements to metadata extraction, imports, sections, or resources are welcome — provided they remain:

- static
- deterministic
- dependency‑minimal

### Add synthetic test samples

We do **not** accept real malware samples.
See the “Testing” section below.

### Improve documentation

Better examples, diagrams, and explanations are always appreciated.

---

## Contribution Process

1. **Fork the repository**

```bash
git clone https://github.com/iocx-dev/iocx.git
```

2. **Create a feature branch**

```bash
git checkout -b feature/my-improvement
```

3. **Install locally**

```bash
pip install -e .
```

4. **Run tests**

```bash
pytest
```

5. **Run security checks**

```bash
bandit -r iocx -lll
pip-audit --skip-editable
```

6. **Open a Pull Request**

- Target the `main` branch
- Describe what you changed and why
- Link any related issues

CI will run automatically.

---

## Testing

IOCX is designed to be **safe to develop on any machine**.

### Do NOT:

- upload or commit real malware
- submit password‑protected malware archives
- include malicious payloads or exploit code
- add samples requiring execution to analyse

### Do:

- use synthetic PE files
- embed fake IOCs inside harmless executables
- use benign Windows binaries for structural testing
- use public test files like EICAR or GTUBE
- add text files containing mixed IOCs

If unsure, open an issue before submitting.

### Tests

All new features should include tests.
Bug fixes should include a test that reproduces the issue.

Tests live in:

```
tests/
```

We use pytest.

---

## Adding New Extractors

Extractors live in:

```
iocx/detectors/extractors/
```

To add one:

- create a new file in that directory
- follow existing patterns
- ensure it registers itself on import
- add tests under `tests/unit/extractors/`

Extractors must be:

- deterministic
- side‑effect‑free
- safe for untrusted input

---

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

---

## Security

If you discover a security issue, do not open a GitHub issue.
Follow the instructions in `SECURITY.md`.

---

## Code of Conduct

Be respectful, constructive, and supportive.
We aim for a collaborative, professional environment.

---

## Licensing of Contributions

By contributing to IOCX, you agree that:

- Your contributions are licensed under the **Mozilla Public License 2.0 (MPL‑2.0)**.
- You grant the project maintainers the right to **dual‑license your contributions** under commercial terms as part of the IOCX open‑core model.
- You retain copyright to your contributions.

This ensures:

- the open‑source core remains healthy
- improvements remain open
- commercial customers can use IOCX under proprietary terms
- your work is properly attributed

By submitting a contribution, you certify that you have the right to do so and that your contribution does not violate any third-party rights.

---

## Trademark Notice

Contributors may not use the IOCX name in a way that implies endorsement.
See [TRADEMARK_POLICY.md](TRADEMARK_POLICY.md) for details.
See [LICENSE](LICENSE) for full MPL-2.0 terms.

---

## Thank You

Your contributions help make IOCX better for everyone.
We’re grateful for your time, ideas, and expertise.
