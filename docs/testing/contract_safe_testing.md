# Contract‑Safe Testing Strategy for IOCX

## Philosophy

> Same file, same output, every time.

This document defines the layered, snapshot‑based testing strategy that ensures IOCX remains deterministic, stable, and predictable across versions.

## Scope

This document defines the testing strategy for deterministic PE parsing, heuristic evaluation, IOC extraction, and schema normalisation within IOCX.

## Abstract

Deterministic IOC extraction is a foundational requirement for reproducible malware analysis, longitudinal threat intelligence, and automated security pipelines. Variability in extraction results—whether caused by nondeterministic parsing, heuristic drift, or environment‑dependent behaviour—introduces noise that propagates through downstream systems, undermining correlation, deduplication, and historical comparison. To address this, IOCX adopts a contract‑safe testing model in which each binary is treated as an immutable input–output pair. Once a file enters the test suite, its complete structured output is frozen as a golden snapshot. Any deviation from this snapshot is treated as a contract violation unless explicitly reviewed and approved. This approach ensures that the IOCX pipeline remains stable across code changes, dependency updates, and heuristic refinements. By enforcing deterministic behaviour at every stage—PE parsing, heuristic evaluation, IOC extraction, and schema normalisation—IOCX provides a reproducible analytical foundation suitable for research, automation, and long‑term threat intelligence operations.

## Introduction

Deterministic IOC extraction is critical for reliable threat intelligence, automated triage, and reproducible malware analysis. However, many commercial and open‑source tools exhibit nondeterministic behaviour due to heuristic instability, inconsistent parsing logic, environment‑specific dependencies, or silent updates that alter output formats. These inconsistencies lead to divergent results for identical inputs, breaking correlation pipelines, invalidating baselines, and eroding analyst trust. IOCX addresses this systemic problem through a contract‑safe testing strategy that treats each binary as a fixed behavioural contract. Once a sample is added to the test suite, its full structured output is captured as a golden snapshot and must remain stable across all future versions of the tool. Any deviation—whether caused by code changes, library upgrades, or heuristic adjustments—is flagged as a contract violation unless explicitly approved. This methodology ensures reproducibility, guards against regression, and provides a stable analytical substrate that other tools often fail to guarantee. By formalising determinism as a first‑class requirement, IOCX avoids the common pitfalls of heuristic drift and nondeterministic extraction, delivering consistent results suitable for long‑term operational use.

Contract-safe testing is split into four distinct layers. The following sections formalise the layered testing model and describe how IOCX enforces deterministic behaviour across all classes of inputs.

## Layer Model

### Layer 1: Core behaviour

Layer 1 exists to guarantee that IOCX’s fundamental behaviour is stable, predictable, and correct under normal operating conditions. These inputs are intentionally simple, well‑formed, and representative of the kinds of binaries encountered in everyday triage workflows. The goal is not to test edge cases or adversarial conditions, but to ensure that the core extraction engine, metadata pipeline, and section‑level analysis behave deterministically when the input is valid and unambiguous.

This layer establishes the baseline contract for IOCX:

- literal IOCs must be extracted consistently
- metadata fields must be populated correctly
- section parsing must be stable
- no false positives should appear
- output structure must remain unchanged across versions

Layer 1 provides the “ground truth” against which all higher layers are measured. If a change breaks a Layer 1 test, it indicates a regression in fundamental behaviour rather than an improvement in edge‑case handling. These tests ensure that IOCX’s core remains reliable even as the heuristics engine and adversarial handling evolve.

### Layer 2: Edge cases

Layer 2 exists to validate IOCX’s behaviour on inputs that are technically valid but structurally unusual, ambiguous, or borderline. These binaries sit between “normal” and “adversarial”: they follow the PE specification, but they stress the parser in ways that real‑world samples often do — unusual alignments, sparse sections, oversized directories, mixed encodings, or uncommon metadata layouts.

The purpose of this layer is to ensure that IOCX handles these edge‑case conditions:

- without crashing
- without misclassifying benign anomalies as malicious
- without producing inconsistent or unstable output
- without leaking internal parsing state into the public API

Layer 2 tests the robustness of the extraction and parsing logic when confronted with inputs that are legal but unexpected. These cases frequently appear in:

- packer stubs
- compiler‑generated oddities
- embedded resources
- installers
- non‑malicious but unconventional binaries

This layer ensures IOCX remains resilient and predictable even when the input stretches the boundaries of what “normal” looks like.

### Layer 3: Adversarial inputs

Layer 3 exists to ensure IOCX behaves predictably when confronted with inputs that are malformed, adversarial, or structurally contradictory — the kinds of binaries real‑world DFIR tools encounter but compilers never produce. These samples are designed to break assumptions, violate the PE specification, and trigger edge‑case logic paths. The goal is not to test correctness against “valid” binaries, but to guarantee that IOCX remains stable, deterministic, and safe even when the input is hostile, corrupted, or intentionally evasive.

### Layer 4: Regression tests

Layer 4 exists to ensure that previously fixed bugs never reappear. These samples are not designed to be adversarial or structurally interesting — they are historical reproductions of issues that IOCX has already encountered and resolved. Each binary in this layer corresponds to a specific past failure mode: a crash, a hang, a mis‑extraction, a mis‑classification, or an incorrect metadata interpretation.

The purpose of this layer is simple but critical:

- If IOCX ever regresses on a previously fixed behaviour, Layer 4 catches it immediately.
- If a refactor or heuristic change alters output in an unintended way, Layer 4 highlights it.
- If a new feature accidentally reintroduces an old bug, Layer 4 prevents it from shipping.

Regression tests form the long‑term memory of the project. They ensure that as IOCX grows more capable — with new heuristics, deeper analysis, and more complex adversarial handling — it never loses correctness on the behaviours it has already mastered.

Layer 4 is what allows IOCX to evolve confidently without fear of breaking the past.

## Directory Structure

```plaintext
tests/
└── contract/
    │
    ├── fixtures/
    │ ├── layer1_core/
    │ ├── layer2_edge/
    │ ├── layer3_adversarial/
    │ └── layer4_regressions/
    ├── snapshots/
    │ ├── layer1_core/
    │ ├── layer2_edge/
    │ ├── layer3_adversarial/
    │ └── layer4_regressions/
    └── test_pipeline.py
```

## Naming Conventions

### Fixtures (binaries)

Use:

```plaintext
<category>_<descriptive_name>.<analysis_level>.<ext>
```
Examples:

- `clean_iocx_demo.core.exe`
- `upx_packed.full.exe`
- `unicode_homoglyph_domains.full.bin`
- `2026_04_bug1234_minimal_repro.full.exe`

### Snapshots (JSON)

Mirror the fixture name:

```plaintext
<same_name>.json
```

This ensures:

- 1:1 mapping
- Easy diffing
- Easy regeneration

### Regression naming

Use:

```plaintext
<YYYY>_<MM>_<bug_id>_<short_description>.exe
```

This encodes:

- chronology
- bug lineage
- reproducibility

## Matrix

This matrix defines the minimum viable set of binaries required to lock in deterministic behaviour across normal, edge‑case, adversarial, and regression scenarios.

### Layer 1 — Core Behaviour (4–6 binaries)

Representative, non-complex, realistic binaries that exercise the main parsing paths.

These are the **baseline contract**. If any of these outputs change, it must be intentional and reviewed.

| Sample                                                         | Why it matters                                                              |
|----------------------------------------------------------------|-----------------------------------------------------------------------------|
| **1. Clean IOCX demo PE**                                      | Locks in baseline behaviour for simple EXEs, fixed strings, normal imports. |
| **2. Typical Windows‑like system binary** (e.g., notepad‑like) | Tests imports, exports, signatures, timestamps, sections.                   |
| **3. Statically linked executable**                            | Minimal imports, simple section layout, tests fallback logic.               |
| **4. Typical compiler‑produced PE** (MSVC or MinGW)            | Normal import table, standard sections, realistic metadata.                 |
| **5. .NET assembly**                                           | Tests CLR header, metadata directories, managed PE quirks.                  |
| **6. Signed binary**                                           | Tests deterministic signature extraction and certificate chain handling.    |

*This is an aspirational list and does not represent the core behaviour input corpus. It will be added to gradually.*

Tests for each sample

- PE metadata snapshot
- IOC extraction snapshot
- Heuristic snapshot
- End‑to‑end final JSON snapshot

These snapshots become the IOCX contract.

### Layer 2 — Edge Cases (6–10 binaries)

Weird, malformed, or unusual binaries that stress the parser but are not hostile.

| Sample                                        | Why it matters                                            |
|-----------------------------------------------|-----------------------------------------------------------|
| **1. UPX‑packed binary**                      | Tests high entropy, packer heuristics, section anomalies. |
| **2. Import‑by‑ordinal binary**               | Tests ordinal handling and import table robustness.       |
| **3. Binary with broken imports**             | Tests graceful degradation and fallback logic.            |
| **4. Binary with weird TLS directory**        | Tests TLS parsing, callback handling, anomalies.          |
| **5. Binary with oversized** `.rsrc`          | Tests resource directory traversal.                       |
| **6. Binary with tiny** `.text` **section**   | Tests entropy heuristics and section validation.          |
| **7. Binary with overlapping sections**       | Tests section boundary validation.                        |
| **8. Binary with malformed PE header**        | Tests “best effort” parsing.                              |
| **9. Binary with unusual subsystem**          | Tests subsystem parsing and normalisation.                |
| **10. Binary with sparse import table**       | Tests import enumeration stability.                       |

*This is an aspirational list and does not represent the current edge case input corpus. It will be added to gradually.*

Tests for each sample:

- Metadata snapshot
- Heuristic snapshot
- End‑to‑end snapshot
- Assertions that the parser **does not crash**
- Assertions that heuristics fire **predictably**

### Layer 3 — Adversarial Inputs (6–10 binaries)

Inputs designed to break regexes, confuse parsers, or trigger fallback logic.

| Sample                                                                                | Why it matters                                                                                                                                                                                                                                        |
|---------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1. Heuristics-rich PE (heuristics_rich.full.exe)**                                  | Exercises full-analysis heuristic engine (see [Appendix 3.1](/docs/testing/appendices/heuristic_rich.full.exe.md))                                                                                                                                    |
| **2. Binary with high‑entropy crypto‑like payload (crypto_entropy_payload.full.exe)** | Tests entropy analysis and payload‑like sections (see [Appendix 3.2](/docs/testing/appendices/crypto_entropy_payload.full.exe.md))                                                                                                                    |
| **3. Binary with obfuscated string patterns (string_obfuscation_tricks.full.exe)**    | Ensures only literal IOCs are extracted (see [Appendix 3.3](/docs/testing/appendices/string_obfuscation_tricks.full.exe.md))                                                                                                                          |
| **4. Franken malformed PE (franken_malformed_pe.full.exe)**                           | Exercises structural-anomaly heuristics using a hand-crafted PE with contradictory headers, overlapping sections, invalid directories, and out-of-bounds entrypoint (see [Appendix 3.4](/docs/testing/appendices/franken_malformed_pe.full.exe.md))   |
| **5. Binary with intentionally corrupted import table (malformed_import_table.full.exe)**                    | Validates resilience against malformed PE import tables by forcing the parser to handle out‑of‑range RVAs, invalid directory sizes, and missing import descriptors without crashing or producing false IOCs (see [Appendix 3.5](/docs/testing/appendices/malformed_import_table.full.exe.md))   |
| **6. Invalid section alignment (invalid_section_alignment.full.exe)**                 | Validates behaviour when section raw offsets violate FileAlignment and raw/virtual sizes contradict each other (see [Appendix 3.6](/docs/testing/appendices/invalid_section_alignment.full.exe.md))   |
| **7. Binary containing fake PE headers in data**                                      | Tests header‑detection logic.                                                                                                                                                                                                                         |
| **8. Binary with extremely long path‑like strings**                                   | Tests IOC extraction limits.                                                                                                                                                                                                                          |
| **9. Binary with Unicode homoglyph domains**                                          | Tests domain normalisation.                                                                                                                                                                                                                           |
| **10. Binary with malformed URLs**                                                     | Tests URL extraction robustness.                                                                                                                                                                                                                      |
| **11. Binary with mixed‑script IOCs**                                                  | Tests regex boundaries and Unicode handling.                                                                                                                                                                                                          |
| **12. Binary with deeply nested escape sequences**                                    | Tests regex backtracking safety.                                                                                                                                                                                                                      |
| **13. Binary with corrupted section table**                                           | Tests fallback parsing.                                                                                                                                                                                                                               |
| **14. Binary with random high‑entropy strings**                                       | Tests false‑positive suppression.                                                                                                                                                                                                                     |
| **15. Binary with misleading import names**                                           | Tests import heuristics.                                                                                                                                                                                                                              |
| **16. Binary with intentionally broken RVA/offsets**                                  | Tests error‑tolerant parsing.                                                                                                                                                                                                                         |

*This is an aspirational list and does not represent the current adversarial input corpus. It will be added to gradually.*

Tests for each sample

- End‑to‑end snapshot
- Assertions that:
   - Output is **valid JSON**
   - No crashes or hangs occur
   - Fallback behaviour is **deterministic**

### Layer 4 — Regression Tests (grows over time)

Every bug fixed becomes a new golden test.

**Process:**

1. Capture the offending file (or minimal reproducer).
2. Add it to `tests/contract/fixtures/layer4_regressions/`.
3. Generate the correct output.
4. Snapshot it.
5. Never delete it.

**Guarantee:**

No fixed bug ever returns.

### Matrix Summary

**Layer 1 — Core (6 samples)**

- Clean IOCX demo PE
- Windows‑like system binary
- Statically linked EXE
- Typical compiler‑produced EXE
- .NET assembly
- Signed binary

**Layer 2 — Edge cases (10 samples)**

- UPX‑packed
- Ordinal imports
- Broken imports
- Weird TLS
- Oversized `.rsrc`
- Tiny `.text`
- Overlapping sections
- Malformed header
- Unusual subsystem
- Sparse import table

**Layer 3 — Adversarial (10 samples)**

- Fake PE headers
- Very long paths
- Unicode homoglyph domains
- Malformed URLs
- Mixed‑script IOCs
- Deep escape sequences
- Corrupted section table
- Random entropy strings
- Misleading import names
- Broken RVAs

**Layer 4 — Regression (unbounded)**

Every bug fixed becomes a new golden test.

### Final note

Together, these samples form the minimal baseline required to guarantee deterministic behaviour across the full spectrum of realistic, edge-case, and adversarial PE inputs.
This matrix gives:

- Breadth (normal → weird → hostile)
- Depth (metadata → heuristics → IOCs → final schema)
- Determinism (snapshots freeze behaviour)
- Longevity (regressions accumulate forever)

It is the smallest set that enforces the promise:

> Same file, same output, every time.

## Snapshot Policy

### Golden binaries

- Stored under version control or content‑addressed storage.
- Never rebuilt during tests.
- Immutable.

### Golden outputs

- Stored as JSON snapshots.
- Any change requires:
   - Explicit regeneration
   - Code review
   - A commit message explaining why the contract changed

Snapshots are the **contract.**

## Test Harness

Below is a minimal, production‑ready test harness using pytest.

It performs:

- fixture discovery
- pipeline execution
- snapshot comparison
- automatic diffing
- deterministic output enforcement

```python
import json
import pathlib
import pytest
from iocx.engine import Engine

@pytest.fixture
def engine():
    return Engine()


FIXTURES_DIR = pathlib.Path("tests/contract/fixtures")
SNAPSHOTS_DIR = pathlib.Path("tests/contract/snapshots")


def load_snapshot(snapshot_path):
    with open(snapshot_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_snapshot(snapshot_path, data):
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def discover_fixtures():
    """Yield (fixture_path, snapshot_path) pairs for all layers."""
    for fixture in FIXTURES_DIR.rglob("*"):
        if fixture.is_file() and fixture.suffix.lower() in ('.exe', '.bin'):
            rel = fixture.relative_to(FIXTURES_DIR)
            snapshot = SNAPSHOTS_DIR / rel.with_suffix(".json")
            yield fixture, snapshot

@pytest.mark.contract
@pytest.mark.parametrize("fixture_path,snapshot_path", discover_fixtures())
def test_contract_safe_pipeline(engine, fixture_path, snapshot_path):

    output = engine.extract(fixture_path)

    # Normalise file path to string for deterministic snapshot comparison
    if isinstance(output.get("file"), pathlib.Path):
        output["file"] = str(output["file"])

    if not snapshot_path.exists():
        # First run: create snapshot
        save_snapshot(snapshot_path, output)
        pytest.fail(f"Snapshot created for {fixture_path}, please review and re-run.")

    expected = load_snapshot(snapshot_path)

    assert output == expected, (
        f"Contract violation for {fixture_path}.\n"
        f"Snapshot: {snapshot_path}\n"
        f"Output differs from expected."
    )
```

### How This Harness Enforces The Contract

**1. Automatic fixture discovery**

Every binary in `tests/contract/fixtures/**` is automatically tested.

**2. Snapshot enforcement**

If a snapshot doesn’t exist:

- It is created
- The test fails
- You review and commit intentionally

**3. Byte‑for‑byte comparison**

The final JSON output must match the snapshot exactly:

- field names
- field order
- normalisation
- casing
- heuristics
- IOCs
- metadata

**4. Zero tolerance for accidental changes**

Any deviation is a contract violation.

### What This Gives You

- A **deterministic, reproducible, future‑proof** test suite.
- A clear separation between:
  - normal behaviour
  - edge cases
  - adversarial inputs
  - regressions
- A structure that scales indefinitely.
- A harness that enforces the **core promise**:

> Same file, same output, every time
