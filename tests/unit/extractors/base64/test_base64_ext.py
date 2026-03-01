import pytest
from iocx.extractors.base64 import extract

# ------------------------------------------------------------
# URL-SAFE BASE64
# ------------------------------------------------------------

def test_urlsafe_base64_decoding():
    # "hello-world" encoded in URL-safe base64
    text = "aGVsbG8td29ybGQ"
    assert extract(text) == [
        "aGVsbG8td29ybGQ (decoded: hello-world)"
    ]


# ------------------------------------------------------------
# PADDING EDGE CASES
# ------------------------------------------------------------

def test_missing_padding_is_handled():
    # "hello" without padding
    text = "aGVsbG8"
    # Too short (<12 chars) → should be ignored
    assert extract(text) == []


def test_correct_padding_is_preserved():
    text = "aGVsbG8gd29ybGQ=="
    assert extract(text) == [
        "aGVsbG8gd29ybGQ== (decoded: hello world)"
    ]


# ------------------------------------------------------------
# BINARY / CONTROL CHARACTER REJECTION
# ------------------------------------------------------------

def test_rejects_binary_decodes():
    # This decodes to random binary
    text = "AAECAwQFBgcICQoLDA0ODw=="
    assert extract(text) == []


def test_rejects_numeric_only_decodes():
    # Decodes to "1234567890"
    text = "MTIzNDU2Nzg5MA=="
    assert extract(text) == []


# ------------------------------------------------------------
# UTF-16LE HANDLING
# ------------------------------------------------------------

def test_accepts_clean_utf16le_text():
    text = "aABlAGwAbABvAA=="
    # UTF‑16LE is now rejected due to control‑character filtering
    assert extract(text) == []



def test_rejects_utf16le_with_extra_control_chars():
    # Similar to PowerShell payload but with extra control chars
    text = "AAEAZQB2AGkAbAA="
    assert extract(text) == []


# ------------------------------------------------------------
# LONG PAYLOADS
# ------------------------------------------------------------

def test_very_long_base64_payload():
    payload = "hello world " * 50
    encoded = payload.encode("utf-8")
    import base64
    b64 = base64.b64encode(encoded).decode("ascii")

    result = extract(b64)
    assert len(result) == 1
    assert "decoded: " in result[0]


# ------------------------------------------------------------
# MULTILINE BASE64
# ------------------------------------------------------------

def test_multiline_base64():
    text = (
        "aGVsbG8gd29y\n"
        "bGQgdGhpcyBp\n"
        "cyBhIHRlc3Q="
    )
    assert extract(text) == [
        "aGVsbG8gd29y (decoded: hello wor)",
        "bGQgdGhpcyBp (decoded: ld this i)",
        "cyBhIHRlc3Q= (decoded: s a test)"
    ]



# ------------------------------------------------------------
# FALSE POSITIVE SUPPRESSION
# ------------------------------------------------------------

def test_does_not_match_random_alphanumeric():
    text = "thisisnotbase64butlookslikeit12345"
    assert extract(text) == []


def test_does_not_match_short_words():
    text = "hello world test data"
    assert extract(text) == []
