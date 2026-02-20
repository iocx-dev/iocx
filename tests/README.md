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
