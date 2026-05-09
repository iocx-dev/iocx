# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.base64 import extract

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # URL-safe base64 (decoded: hello-world)
    (
        "aGVsbG8td29ybGQ",
        ["aGVsbG8td29ybGQ"]
    ),

    # Correct padding preserved (decoded: hello world)
    (
        "aGVsbG8gd29ybGQ==",
        ["aGVsbG8gd29ybGQ=="]
    ),

    # Very long payload
    (
        # "hello world " * 50 encoded
        "aGVsbG8gd29ybGQg" * 50,
        None # handled separately below
    ),

    # Multiline base64 (decoded: hello wor ld this i s a test)
    (
        "aGVsbG8gd29y\nbGQgdGhpcyBp\ncyBhIHRlc3Q=",
        [
            "aGVsbG8gd29y",
            "bGQgdGhpcyBp",
            "cyBhIHRlc3Q="
        ]
    ),
])
def test_base64_positive(text, expected):
    out = extract(text)

    # Special handling for the "very long payload" case
    if expected is None:
        assert len(out) == 1
        return

    assert [d.value for d in out] == expected


# ------------------------------------------------------------
# NEGATIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text", [

    # Missing padding but too short (<12 chars)
    "aGVsbG8",

    # Invalid base64
    "notbase64@@@",

    # Binary decode → rejected
    "AAECAwQFBgcICQoLDA0ODw==",

    # Numeric-only decode → rejected
    "MTIzNDU2Nzg5MA==",

    # UTF‑16LE clean text → rejected due to control chars
    "aABlAGwAbABvAA==",

    # UTF‑16LE with extra control chars
    "AAEAZQB2AGkAbAA=",

    # Random alphanumeric noise
    "thisisnotbase64butlookslikeit12345",

    # Short words
    "hello world test data",
])
def test_base64_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
