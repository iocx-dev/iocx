# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.parsers.string_extractor import (
    extract_strings_from_bytes,
    extract_strings,
    MAX_STRING_LEN,
)


def test_ascii_basic():
    data = b"hello world 123"
    result = extract_strings_from_bytes(data, min_length=3)
    assert result == ["hello world 123"]


def test_ascii_min_length():
    data = b"abcd ef"
    result = extract_strings_from_bytes(data, min_length=4)
    assert result == ["abcd ef"]


def test_utf16le_basic():
    data = "HELLO".encode("utf-16le")
    result = extract_strings_from_bytes(data, min_length=3)
    assert result == ["HELLO"]


def test_utf16le_mixed_with_ascii():
    ascii_part = b"test123"
    utf16_part = "WORLD".encode("utf-16le")
    data = ascii_part + b"\x00" + utf16_part
    result = extract_strings_from_bytes(data, min_length=3)
    assert result == ["test123", "3WORLD"]


def test_deduplication_preserves_order():
    data = b"hello hello hello"
    result = extract_strings_from_bytes(data, min_length=3)
    assert result == ["hello hello hello"]


def test_max_length_ascii():
    long_string = b"a" * (MAX_STRING_LEN + 10)
    result = extract_strings_from_bytes(long_string, min_length=4)
    assert result == []


def test_max_length_utf16le():
    long_utf16 = ("A" * (MAX_STRING_LEN + 10)).encode("utf-16le")
    result = extract_strings_from_bytes(long_utf16, min_length=4)
    assert result == []


def test_empty_input():
    result = extract_strings_from_bytes(b"", min_length=4)
    assert result == []


def test_extract_strings_reads_file(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"hello world")
    result = extract_strings(str(p), min_length=3)
    assert result == ["hello world"]
