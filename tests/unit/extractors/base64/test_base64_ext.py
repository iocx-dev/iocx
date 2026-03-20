import pytest
from iocx.detectors.extractors.base64 import extract

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # URL-safe base64
    (
        "aGVsbG8td29ybGQ",
        ["aGVsbG8td29ybGQ (decoded: hello-world)"]
    ),

    # Correct padding preserved
    (
        "aGVsbG8gd29ybGQ==",
        ["aGVsbG8gd29ybGQ== (decoded: hello world)"]
    ),

    # Very long payload
    (
        # "hello world " * 50 encoded
        "aGVsbG8gd29ybGQg" * 50,
        None # handled separately below
    ),

    # Multiline base64
    (
        "aGVsbG8gd29y\nbGQgdGhpcyBp\ncyBhIHRlc3Q=",
        [
            "aGVsbG8gd29y (decoded: hello wor)",
            "bGQgdGhpcyBp (decoded: ld this i)",
            "cyBhIHRlc3Q= (decoded: s a test)"
        ]
    ),
])
def test_base64_positive(text, expected):
    out = extract(text)

    # Special handling for the "very long payload" case
    if expected is None:
        assert len(out) == 1
        assert "decoded: " in out[0].value
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
