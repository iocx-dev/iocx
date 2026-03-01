# Welcome

Thank you for your interest in contributing to malx‑ioc‑extractor. This project is part of the MalX Labs ecosystem — a collection of modern, developer‑friendly security tools focused on safe, scalable analysis.

We appreciate improvements of all kinds — bug fixes, new extractors, documentation updates, and thoughtful discussions.

This guide explains how to contribute effectively and keep the project consistent and maintainable.

## Project Philosophy

This project is intentionally:

- Minimal — very small dependency footprint
- Secure — safe handling of untrusted input
- Predictable — deterministic behaviour, no network access
- Extensible — new extractors and parsers can be added cleanly

Contributions should align with these principles.

## How to Contribute

There are several ways to contribute:

### Fix bugs

Open an issue or submit a PR with a clear description.

### Add new IOC detectors

Regex‑based detectors live under `extractors/`.
Please include:

- a clear regex
- validation logic
- test cases
- examples

### Improve PE parsing

Enhancements to metadata extraction, imports, sections, or resources are welcome.

### Add synthetic test samples

We do **not** accept real malware samples.
See the “Testing” section below.

### Improve documentation

Better examples, diagrams, or explanations are always appreciated.

### Process

1. Fork the repository

Create your own fork and clone it locally:
```bash

git clone https://github.com/malx-labs/malx-ioc-extractor.git

```

2. Create a feature branch

Use a descriptive branch name:
```bash

git checkout -b feature/my-improvement

```

3. Install the project locally

Use a virtual environment:
```bash

pip install -e .

```

4. Run tests

Before submitting changes:
```bash

pytest

```

5. Run security checks

We use Bandit and pip‑audit:
```bash

bandit -r iocx -lll
pip-audit --skip-editable

```

6. Open a Pull Request

When your changes are ready:

- Open a PR against the main branch
- Describe what you changed and why
- Link any related issues

CI will run automatically on your PR.

## Testing

This project is designed to be **safe to develop on any machine**.

To maintain that:

### Do NOT:

- Upload or commit real malware
- Submit password‑protected malware archives
- Include malicious payloads, droppers, or exploit code
- Add samples that require execution to analyse

### Do:

- Use synthetic PE files
- Embed fake IOCs inside harmless executables
- Use benign Windows binaries for structural testing
- Use public test files like EICAR or GTUBE
- Add text files containing mixed IOCs

If you’re unsure whether a sample is safe, open an issue first.

### Tests

All new features should include tests.
If you fix a bug, please add a test that reproduces it.

Unit and integration tests live in:
```plaintext

tests/

```

We use pytest for the test suite.

## Adding New Extractors

Extractor modules live in:
```plaintext

iocx/extractors/

```

To add a new extractor:

- Create a new file in that directory
- Implement a class or function following existing patterns
- Ensure it registers itself on import
- Add tests under tests/unit/extractors/

Keep extractors:

- deterministic
- side‑effect‑free
- safe for untrusted input

## Code Style

We keep the codebase clean and consistent.

- Use Black for formatting
- Use Ruff for linting (locally; CI does not enforce linting)
- Follow existing module structure and naming conventions, adhering to PEP8 for Python code

Run locally:
```bash

ruff check iocx
black iocx

```

## Security

If you discover a security issue, do not open a GitHub issue.

Please follow the instructions in SECURITY.md.

## Code of Conduct

By participating, you agree to uphold a respectful and constructive environment.
Be kind, be clear, and help others succeed.

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

## Thank You

Your contributions help make this project better for everyone.
We’re grateful for your time, ideas, and expertise.
