# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.filepaths import extract

NON_ASCII_CASES = [

    # Unicode inside directory names
    ("/tмp/file.txt", []),
    ("C:\\Usеrs\\Public\\run.exe", ["C:\\Usеrs\\Public\\run.exe"]),

    # Unicode separators
    ("/usr\u2215bin\u2215python3", []),
    ("C:\u2215Windows\u2215System32\u2215cmd.exe", []),

    # Zero‑width characters
    ("/tmp/\u200bfile.txt", []),
    ("C:\\Temp\\\u200dmal.exe", ["C:\\Temp\\\u200dmal.exe"]),

    # RTL overrides
    ("/var/log/\u202Eevil.txt", []),
    ("C:\\Temp\\\u202ebad.dll", ["C:\\Temp\\\u202ebad.dll"]),

    # Unicode whitespace
    ("/etc/\u00A0shadow", []),
    ("C:\\Windows\\System32\\\u2003calc.exe", []),

    # Null bytes
    ("/tmp/\u0000file.txt", []),
    ("C:\\Temp\\\x00evil.exe", ["C:\\Temp\\\x00evil.exe"]),
]

WINDOWS_UNICODE_ALLOWED = [
    ("C:\\Usеrs\\Public\\run.exe", ["C:\\Usеrs\\Public\\run.exe"]),
    ("C:\\Temp\\\u200dmal.exe", ["C:\\Temp\\\u200dmal.exe"]),
    ("C:\\Temp\\\u202ebad.dll", ["C:\\Temp\\\u202ebad.dll"]),
    ("C:\\Temp\\\x00evil.exe", ["C:\\Temp\\\x00evil.exe"]),
]

UNIX_UNICODE_REJECTED = [
    ("/tмp/file.txt", []),
    ("/usr/\u200bfile.txt", []),
    ("/var/log/\u202Eevil.txt", []),
    ("/etc/\u00A0shadow", []),
]

@pytest.mark.parametrize("sample, expected", NON_ASCII_CASES)
def test_non_ascii_invalidates_path(sample, expected):
    out = extract(sample)
    values = [d.value for d in out]
    assert values == expected

@pytest.mark.parametrize("sample, expected", WINDOWS_UNICODE_ALLOWED)
def test_windows_unicode_allowed(sample, expected):
    out = extract(sample)
    values = [d.value for d in out]
    assert values == expected

@pytest.mark.parametrize("sample, expected", UNIX_UNICODE_REJECTED)
def test_unix_unicode_rejected(sample, expected):
    out = extract(sample)
    values = [d.value for d in out]
    assert values == expected
