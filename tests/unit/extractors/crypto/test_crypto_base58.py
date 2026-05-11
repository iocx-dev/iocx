# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from iocx.detectors.extractors.crypto import extract, base58check_decode
from iocx.models import Detection
import pytest

def test_btc_valid_base58check():
    # These are real, valid Base58Check P2PKH addresses
    text = "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please and to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    result = extract(text)
    values = [d.value for d in result]
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in values
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values

def test_btc_invalid_checksum():
    text = "1BoatSLRHtKNngkdXEeobR76b53LETtpy" # invalid
    result = extract(text)
    assert result == []


def test_btc_case_sensitivity():
    text = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 1a1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    result = extract(text)

    # Only the uppercase version is valid Base58Check
    assert any(d.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" for d in result)


def test_base58check_decode_invalid_character():
    with pytest.raises(ValueError, match="Invalid Base58 character"):
        base58check_decode("10") # "0" is not valid Base58


def test_base58check_decode_too_short():
    with pytest.raises(ValueError, match="Too short for Base58Check"):
        base58check_decode("1") # decodes to b"\x00" → too short
