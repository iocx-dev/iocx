import pytest
from iocx.extractors.hashes import extract

# ------------------------------------------------------------
# VALID HASHES
# ------------------------------------------------------------

def test_md5_hash():
    text = "The file hash is d41d8cd98f00b204e9800998ecf8427e"
    assert extract(text) == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_sha1_hash():
    text = "sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert extract(text) == ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]


def test_sha256_hash():
    text = "hash= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert extract(text) == [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]


def test_sha512_hash():
    text = (
        "sha512: "
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    assert extract(text) == [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ]


def test_mixed_case_hash():
    text = "MD5: A1b2C3d4E5f60718293a4Bc5D6e7F890"
    assert extract(text) == ["A1b2C3d4E5f60718293a4Bc5D6e7F890"]


# ------------------------------------------------------------
# MULTIPLE HASHES
# ------------------------------------------------------------

def test_multiple_hashes():
    text = (
        "md5=d41d8cd98f00b204e9800998ecf8427e "
        "sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
    assert extract(text) == [
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ]


# ------------------------------------------------------------
# BOUNDARY BEHAVIOUR
# ------------------------------------------------------------

def test_does_not_match_inside_words():
    text = "prefixd41d8cd98f00b204e9800998ecf8427esuffix"
    assert extract(text) == []


def test_hash_followed_by_punctuation():
    text = "hash: d41d8cd98f00b204e9800998ecf8427e,"
    assert extract(text) == ["d41d8cd98f00b204e9800998ecf8427e"]


# ------------------------------------------------------------
# SHORT HEX BEHAVIOUR
# ------------------------------------------------------------

def test_short_hex_is_captured():
    # The detector intentionally captures 8–31 hex chars
    text = "short hex: deadbeef"
    assert extract(text) == ["deadbeef"]


def test_short_hex_multiple():
    text = "ids: deadbeef cafebabe 1234abcd"
    assert extract(text) == ["deadbeef", "cafebabe", "1234abcd"]


# ------------------------------------------------------------
# FALSE POSITIVE SUPPRESSION
# ------------------------------------------------------------

def test_does_not_match_ipv6():
    text = "IPv6: fe80::1ff:fe23:4567:890a"
    assert extract(text) == []


def test_does_not_match_guid():
    text = "GUID: 550e8400-e29b-41d4-a716-446655440000"
    # Short hex segments ARE matched by design
    assert extract(text) == ["550e8400", "446655440000"]



def test_does_not_match_mac_address():
    text = "MAC: aa:bb:cc:dd:ee:ff"
    assert extract(text) == []


def test_does_not_match_registry_key():
    text = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion"
    assert extract(text) == []


def test_does_not_match_hex_in_url():
    text = "https://example.com/abcd1234efgh5678"
    assert extract(text) == []


def test_does_not_match_memory_address():
    text = "pointer at 0x7ffeefbff5c0"
    assert extract(text) == []
