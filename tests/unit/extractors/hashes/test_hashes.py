# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.hashes import extract

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # MD5
    (
        "The file hash is d41d8cd98f00b204e9800998ecf8427e",
        ["d41d8cd98f00b204e9800998ecf8427e"]
    ),

    # SHA1
    (
        "sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]
    ),

    # SHA256
    (
        "hash= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    ),

    # SHA512 (split across lines in source)
    (
        "sha512: "
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        [
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ]
    ),

    # Mixed case
    (
        "MD5: A1b2C3d4E5f60718293a4Bc5D6e7F890",
        ["A1b2C3d4E5f60718293a4Bc5D6e7F890"]
    ),

    # Multiple hashes
    (
        "md5=d41d8cd98f00b204e9800998ecf8427e "
        "sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709",
        [
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ]
    ),

    # Hash followed by punctuation
    (
        "hash: d41d8cd98f00b204e9800998ecf8427e,",
        ["d41d8cd98f00b204e9800998ecf8427e"]
    ),

    # Short hex (8–31 chars)
    (
        "short hex: 7c12ef9a44",
        ["7c12ef9a44"]
    ),

    # Multiple short hex
    (
        "ids: a3f91c0b2e 9B44EF1280 0012A4FFCC",
        ["a3f91c0b2e", "9B44EF1280", "0012A4FFCC"]
    ),

    # GUID partial capture (by design)
    (
        "GUID: f2ab19c0de-e29b-41d4-a716-446655440000",
        ["f2ab19c0de", "446655440000"]
    ),
])
def test_hash_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


# ------------------------------------------------------------
# NEGATIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text", [

    # Inside words (should not match)
    "prefixd41d8cd98f00b204e9800998ecf8427esuffix",

    # IPv6
    "IPv6: fe80::1ff:fe23:4567:890a",

    # MAC address
    "MAC: aa:bb:cc:dd:ee:ff",

    # Registry key
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion",

    # Hex inside URL
    "https://example.com/abcd1234efgh5678",

    # Memory address
    "pointer at 0x7ffeefbff5c0",
])
def test_hash_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
