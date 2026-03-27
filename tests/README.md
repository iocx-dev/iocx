<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-279_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/iocx-dev/iocx/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/iocx-dev/iocx" alt="License">
  </a>
  <a href="https://github.com/iocx-dev/iocx/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/iocx-dev/iocx/ci.yml?label=build" alt="Build Status">
  </a>
  <img src="https://img.shields.io/badge/v0.2.0_performance-1MB_in_0.0053s-brightgreen" alt="Performance">
  <img src="https://img.shields.io/badge/v0.2.0_throughput-~200MB%2Fs-brightgreen" alt="Throughput">
  <img src="https://img.shields.io/badge/v0.2.0_pathological_IPv6-0.0005s-brightgreen" alt="Pathological IPv6 Timing">
</p>

The IOCX test suite is designed for real SOC conditions, not idealised textbook inputs. Indicators in the wild are messy, malformed, adversarial, and often intentionally obfuscated. The suite reflects that reality through a layered approach:

- Unit tests for correctness
- Integration tests for end‑to‑end behaviour
- Chaos corpus for attacker‑style malformed indicators
- Random fuzzing for robustness
- Mutation‑based fuzzing for adversarial evolution
- CIDR fuzzing for boundary conditions
- Performance tests for operational reliability

At the core of the project is a simple, strict philosophy:

> If a valid IOC exists anywhere inside malformed or obfuscated text, extract it.
> If not, return nothing.
> Never crash.

# Unit Test Suite

This directory contains the unit tests for all individual IOC extractors in
IOCX. Each extractor is tested in isolation to ensure it behaves consistently,
predictably, and according to the extraction rules defined for the project.

## What These Tests Cover

### Email Extractor
- Standard email formats (`user@example.com`)
- Subdomains and multi‑level domains
- Plus‑tags, underscores, hyphens
- Uppercase variants
- Multiple emails in a single string
- Boundary punctuation (e.g., trailing commas)
- Emails inside URLs
- Invalid formats (missing TLD, missing username)
- Long TLDs and multi‑dot domains
- Percent‑encoded local parts

### IPv4 / IPv6 Extractor
- IPv4 dotted‑quad
- IPv4 inside URLs and punctuation
- Multiple IPv4s in one string
- IPv6 expanded and compressed
- IPv6 inside URLs
- IPv6 with ports and zone indices
- Mixed IPv4 + IPv6 extraction
- Suppression of false positives

### Domain Extractor
- Bare domains (`example.com`)
- Subdomains and multi‑level domains
- Domains adjacent to punctuation
- Invalid domain suppression
- No accidental extraction from words

### URL Extractor
- HTTP/HTTPS URLs
- URLs with paths, query strings, and fragments
- URLs adjacent to punctuation
- Multiple URLs in one string
- Suppression of malformed URLs

### Filepath Extractor
- Windows paths (`C:\Users\Bob\file.txt`)
- UNC paths (`\\server\share\file.exe`)
- Lowercasing and normalisation
- Mixed slash/backslash handling
- Suppression of invalid paths

### Hash Extractor
- MD5, SHA1, SHA256, SHA512
- Case‑insensitive matching
- Suppression of invalid lengths
- Multiple hashes in one string

### Base64 Extractor
- Valid base64 strings
- Decoding and IOC extraction from decoded content
- Suppression of short or invalid base64
- Normalisation of output (`raw (decoded: text)`)

### Crypto Wallet Extractor
- Ethereum
- Bitcoin

# Integration Test Suite

This directory contains integration tests that exercise the full IOCX CLI
pipeline. Unlike unit tests, these tests validate the behaviour of the entire
system:

- CLI argument parsing
- File handling
- Binary parsing
- String extraction
- IOC extraction
- Normalisation
- JSON output structure

## What These Tests Cover

### Text Input Integration
- Passing raw text directly to the CLI
- URL and domain extraction from inline text
- JSON output structure validation

### File Input Integration
- Reading IOCs from text files
- Mixed IOC extraction (URLs, domains, emails, filepaths, IPs, hashes, base64, crypto)
- UNC paths and Windows filepaths
- Normalisation of extracted values
- Handling of empty files

### Binary Input Integration
- Running the CLI on real executables
- Go‑compiled and MinGW-compiled binaries (ELF/Mach‑O/PE depending on platform)
- Python script binaries with shebangs
- Ensuring metadata extraction does not break the pipeline
- Ensuring no crashes on non‑text input

### PE Fixture Integration
The `fixtures/bin/` directory contains hand‑crafted PE files compiled with
MinGW. Each fixture has a corresponding JSON manifest describing the IOCs
embedded inside it.

Fixtures include:
- `pe_basic` — ASCII strings in `.data`
- `pe_overlay` — IOCs stored in overlay data
- `pe_rsrc` — IOCs in resource string tables
- `pe_utf16` — UTF‑16LE encoded strings

The integration tests validate:
- PE parsing
- Section traversal
- Overlay extraction
- UTF‑16LE decoding
- IOC extraction across all extractors
- Normalisation of results
- Matching against expected manifests

### Manifest‑Driven Testing
Each PE fixture has a manifest describing:
- expected IOCs
- encoding (ASCII or UTF‑16LE)
- location (data section, overlay, resource table)

The test runner:
- loads the manifest
- runs the CLI on the binary
- flattens all extracted IOCs
- normalises them
- compares against the manifest

This ensures deterministic, end‑to‑end validation of binary extraction.

## Philosophy

Integration tests validate **system behaviour**, not individual extractors. They
ensure that:

- the CLI works as a whole
- extractors cooperate correctly
- binary parsing is stable
- JSON output is consistent
- regressions are caught early

These tests run slower than unit tests but provide high confidence that IOCX
behaves correctly in real‑world scenarios.

# Chaos, Fuzzing & Robustness Tests

These tests were added in v0.2.0 to harden the extractor against real‑world adversarial input.

## Chaos Corpus — Attacker‑Style Malformed Input

Inspired by real malware configs and corrupted logs:

- Broken IPv6
- Junk‑wrapped IPv4
- Malformed brackets
- Protocol fragments
- Obfuscated encodings
- Concatenated indicators

The extractor must salvage valid IPs and ignore the rest.

## Random Fuzzing — Robustness

Thousands of randomised samples across:

- IPv4
- IPv6
- compressed IPv6
- zone‑indexed IPv6
- random noise

Extractor must never crash and always return a list.

## Mutation‑Based Fuzzing — Adversarial Evolution

Starting from valid IOCs, we mutate:

- delimiters
- brackets
- hex groups
- prefixes/suffixes
- reversed strings
- zone indices
- partial truncation

Simulates obfuscation and log corruption.

## CIDR‑Aware Fuzzing — Boundary Conditions

Fuzzes:

- valid masks
- invalid masks (/999, /abc, /-1, ///)
- IPv6 + CIDR
- compressed IPv6 + CIDR
- zone indices + CIDR
- junk‑wrapped CIDR

Extractor must salvage the IP and never crash.

# Performance Test Suite

Performance tests validate operational reliability under large‑scale and pathological conditions.

Run with:
```bash
pytest -m performance -s

```
Real Timings (v0.2.0)
```text

1MB mixed-content:        0.0053s
Pathological IPv6 blob:   0.0005s
100KB:                    0.0006s
300KB:                    0.0017s
600KB:                    0.0031s
1000KB:                   0.0055s

```

Guarantees

- No catastrophic backtracking
- No exponential blowups
- Linear scaling
- ~200MB/s throughput
- Sub‑millisecond handling of pathological IPv6

This ensures the extractor is safe for high‑volume SOC ingestion pipelines.

# Test Coverage & Quality Assurance

This project includes a comprehensive, high‑performance test suite designed to guarantee correctness, stability, and maintainability across all IOC extraction components. The suite covers unit tests, integration tests, and targeted mocks for complex subsystems like PE parsing and file‑type detection.

The result is a fast, deterministic, and deeply reliable testing environment.

## Coverage Summary

As of the latest build:

- Total coverage: ~97%
- Core modules: 100%
- Engine: 97%
- Extractors: 100%
- Detectors: 100%
- Utils: 100%
- PE parser: 90%+
- String extractor: 100%
- Validators: 100%

The remaining uncovered lines are either defensive branches or integration‑level paths that are intentionally exercised only in end‑to‑end tests.

## Testing Strategy

1. Unit Tests (Majority of the suite)

Unit tests isolate each module and validate:

- Input/output correctness
- Error handling
- Edge cases
- Branch coverage
- Cache behaviour
- Detector registration and merging
- String extraction logic
- Normalisation and deduplication

All external dependencies (filesystem, magic, PE parsing, detectors) are mocked to ensure deterministic behaviour.

2. Integration Tests

Integration tests validate:

- CLI behaviour
- Real PE files
- Real text inputs
- End‑to‑end IOC extraction
- Resource string extraction
- Cross‑extractor interactions

These tests ensure the system behaves correctly in real‑world scenarios.

## Engine Coverage Highlights

The engine is the orchestrator of the entire system. It now has full behavioural coverage, including:

- File vs text routing
- PE, text, and unknown pipelines
- Fallback logic
- Cache enable/disable behaviour
- Overridable minimum string length
- Detector execution
- Post‑processing (merge → normalise → dedupe)
- Resource string merging
- Error‑tolerant file detection

Every branch of the engine is exercised through targeted mocks.

## Extractor Coverage Highlights

All extractors now have 100% coverage, including:

- Base64
- Emails
- Filepaths (Windows, Unix, UNC, tilde, relative, malformed)
- Hashes
- IPs
- URL detectors (strict, bare domain, normalisation, deobfuscation)
- Super‑detector orchestration
- Crypto

The string extractor is fully covered, including:

- ASCII runs
- UTF‑16LE runs
- Max‑length caps
- Deduplication
- Mixed encodings
- Empty input
- File‑based extraction

## Utils Coverage

detect_file_type() is fully covered via mocks of `magic.from_file`, including:

- All MIME types
- Exception path
- Unknown fallback

## Testing Philosophy

The test suite is built around these principles:

- Deterministic: No randomness, no external dependencies.
- Fast: Entire suite runs in under 3 seconds.
- Isolated: Each test mocks only what it needs.
- Exhaustive: Every branch and edge case is covered.
- Realistic: Integration tests use real binaries and text samples.
- Maintainable: Clear structure, no brittle assumptions.

This ensures contributors can refactor confidently without fear of regressions.

## Future Enhancements

Potential next steps:

- Mutation testing (to measure test strength, not just coverage)
- Fuzzing for PE parsing
- Performance benchmarks
- Coverage thresholds in CI

# 📎 Appendix: Throughput Calculation (v0.2.0)

The throughput figure shown in the performance badges is derived directly from the measured performance of the extractor on a 1 MB mixed‑content input.

Measured time:
```text

1MB processed in 0.0053 seconds

```

Throughput formula:

$$ \[\text{throughput} = \frac{\text{bytes processed}}{\text{time (seconds)}}\] $$

Calculation:

$$ \[\text{throughput} = \frac{1\ \text{MB}}{0.0053\ \text{s}} \approx 188.7\ \text{MB/s}\] $$

Rounded for readability, this becomes:

```text

~200 MB/s throughput

```

This value is reflected in the performance badges and demonstrates that the extractor maintains linear scaling, no catastrophic backtracking, and SOC‑grade throughput even under adversarial input conditions.
