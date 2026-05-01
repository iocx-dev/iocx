# Contract Test Generators & Integration Sources

This directory contains all C‑based generators used to produce IOCX’s synthetic test binaries. It includes:

- **Contract‑testing generators** (Layer 1–4)
- **Integration‑testing** generators (e.g., `pe_chaos`)

All sources are **synthetic, non‑malicious**, and designed solely to validate IOCX’s deterministic extraction and analysis behaviour.

They contain **no harmful logic**, use only safe test domains and RFC‑5737 IP ranges, and are safe to analyse, compile, and redistribute.

## Directory Structure

```
c/
│
├── contract/ # Sources for Layer 1–4 contract fixtures
│ ├── layer1_core/
│ ├── layer2_edge/
│ ├── layer3_adversarial/
│ └── layer4_regressions/
│
└── integration/ # Sources for integration tests (e.g., pe_chaos)
```

## Contract Generators

These produce the **fixed, committed** binaries used in IOCX’s contract‑testing suite.
Each generator corresponds to a specific behavioural scenario:

- Layer 1 — core behaviour
- Layer 2 — edge cases
- Layer 3 — adversarial inputs
- Layer 4 — regression reproductions

The compiled outputs live in:

```
tests/contract/fixtures/<layer>/
```

These fixtures are committed intentionally to guarantee:

- deterministic extraction across versions
- stable behaviour under normal, edge‑case, and adversarial inputs
- reproducible test results for all contributors
- regression detection as heuristics evolve

## Integration Generators

The `integration/` folder contains C sources used for integration‑level testing, such as:

- stress‑testing the parser
- validating behaviour across multiple code paths
- generating chaotic or fuzz‑like PE structures (`pe_chaos`)
- ensuring the end‑to‑end pipeline behaves consistently

The compiled outputs live in:

```
tests/integration/fixtures/bin/
```

## Compilation

Most generators are simple C files that can be compiled using MSVC or MinGW.

Example (MSVC):

```shell
cl /nologo /O2 /GS- sample.c /link /SUBSYSTEM:WINDOWS
```

Some fixtures (e.g., malformed PE builders) are code‑generated rather than compiled, because compilers cannot produce intentionally invalid PE structures.

## Automatic Build Process (build.ps1)

`build.ps1` provides a fully automated, reproducible build pipeline for all contract‑testing fixtures across all layers.

It:

- compiles all compiler‑based generators
- runs code‑generated builders (e.g., malformed PE constructors)
- cleans previous artefacts to ensure deterministic output
- places all generated binaries into the correct `tests/contract/fixtures/...` directories
- verifies that each fixture exists and matches expected size/structure

The goal is simple:

> **Every contributor, on every machine, produces the exact same test corpus with a single command.**

This prevents fixture drift and ensures snapshot tests remain meaningful across versions and platforms.

Compiled binaries should not be committed here.

They belong in:

```
tests/contract/fixtures/<layer>/
```

A `.gitignore` prevents accidental commits of build artefacts.

## Safety

All generators and all compiled fixtures:

- are synthetic and non‑malicious
- contain no harmful behaviour
- use only safe test domains and reserved IP ranges
- exist solely to validate IOCX’s deterministic extraction engine

They are safe to analyse, execute, and redistribute.

## Contributing

When adding a new generator:

- Ensure the sample is synthetic and harmless
- Document the behaviour or scenario being tested
- Keep runtime behaviour minimal (e.g., a `MessageBoxA` stub)
- For contract fixtures: compile or generate the binary and place it in `tests/contract/fixtures/<layer>/`
- For integration tests: compile or generate the binary and place it in `tests/integration/fixtures/bin/`
- Add a short description to this README
