import pytest
import base64
from iocx.detectors.extractors.base64 import extract


def test_base64_utf16le_like():
    # Construct bytes that look like UTF‑16LE text
    utf16le_bytes = b"A\x00B\x00C\x00D\x00E\x00F\x00"

    # Base64 encode them
    import base64
    b64 = base64.b64encode(utf16le_bytes).decode()

    # Sanity check: decoded bytes match the pattern
    assert base64.b64decode(b64) == utf16le_bytes

    text = f"Here is some data: {b64}"
    results = extract(text)

    assert results == []


def test_base64_utf16le_covers_looks_like_text():

    # UTF‑16LE‑like bytes: A\x00B\x00C\x00D\x00
    utf16le_bytes = b"A\x00B\x00C\x00D\x00"

    b64 = base64.b64encode(utf16le_bytes).decode()

    text = f"Here is some data: {b64}"
    detections = extract(text)

    assert detections == []


def test_base64_invalid_padding_triggers_exception_path():

    # 13 chars, valid base64 charset, but invalid padding → decode() raises
    bad_b64 = "AAAAAAAAAAAAA"

    text = f"Here is some data: {bad_b64}"

    detections = extract(text)

    # The extractor should skip it (exception caught → continue)
    assert detections == []
