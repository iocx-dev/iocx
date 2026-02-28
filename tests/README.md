<p align="center">
  <a href="https://pypi.org/project/iocx/">
    <img src="https://img.shields.io/pypi/v/iocx?logo=pypi&logoColor=white" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-238_passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python Version">
  <a href="https://github.com/malx-labs/malx-ioc-extractor/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/malx-labs/malx-ioc-extractor" alt="License">
  </a>
  <a href="https://github.com/malx-labs/malx-ioc-extractor/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/malx-labs/malx-ioc-extractor/ci.yml?label=build" alt="Build Status">
  </a>
</p>

# Unit Test Suite

This directory contains the unit tests for all individual IOC extractors in
`iocx`. Each extractor is tested in isolation to ensure it behaves consistently,
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
- IPv4 addresses in standard dotted‑quad form
- IPv4 inside URLs and surrounded by punctuation
- Multiple IPv4s in one string
- IPv6 in compressed and expanded forms
- IPv6 inside URLs
- Mixed IPv4 + IPv6 extraction
- Suppression of obvious false positives

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

## Philosophy

Unit tests validate **extractor correctness**, not CLI behaviour. They ensure that
each extractor:

- matches what it should
- rejects what it shouldn’t
- normalises output consistently
- behaves deterministically

These tests run fast and provide immediate feedback during development.

# Integration Test Suite

This directory contains integration tests that exercise the full `iocx` CLI
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
- Mixed IOC extraction (URLs, domains, emails, filepaths, IPs, hashes, base64)
- UNC paths and Windows filepaths
- Normalisation of extracted values
- Handling of empty files

### Binary Input Integration
- Running the CLI on real executables
- Go‑compiled binaries (ELF/Mach‑O/PE depending on platform)
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

These tests run slower than unit tests but provide high confidence that `iocx`
behaves correctly in real‑world scenarios.

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

The string extractor is fully covered, including:

- ASCII runs
- UTF‑16LE runs
- Max‑length caps
- Deduplication
- Mixed encodings
- Empty input
- File‑based extraction

## Utils Coverage

detect_file_type() is fully covered via mocks of magic.from_file, including:

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
