⭐ What Each Folder Covers
test_extractors/

Unit tests for your regex‑based IOC detectors.

Example:

    URLs with/without schemes

    Obfuscated domains (hxxp://example[.]com)

    IPv4/IPv6 edge cases

    Hash length validation

test_parsers/

Tests for your static analysis components:

    PE import table extraction

    Section enumeration

    Resource parsing

    String extraction (ASCII + Unicode)

These tests use synthetic PE files, not malware.

test_validators/

Tests for:

    IOC normalisation

    De‑obfuscation

    Deduplication

    Sorting

test_cli/

Tests that the CLI:

    runs without crashing

    accepts stdin

    outputs valid JSON

    handles missing files gracefully

conftest.py

Holds shared fixtures, such as:

    paths to synthetic samples

    temporary directories

    helper functions
