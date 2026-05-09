# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from iocx.detectors.extractors.crypto import extract, is_valid_btc_address
import hashlib

def test_btc_bech32_detection():
    text = "Bech32 BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    detections = extract(text)

    assert any(
        d.value == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        and d.category == "crypto.btc"
        for d in detections
    )


def test_eth_mixed_case_checksum_detection():
    text = "Checksum ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886E0F7030069857D2E4169EE7"
        and d.category == "crypto.eth"
        for d in detections
    )


def test_eth_lowercase_still_detected():
    text = "Lowercase ETH: 0x52908400098527886e0f7030069857d2e4169ee7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886e0f7030069857d2e4169ee7"
        and d.category == "crypto.eth"
        for d in detections
    )


def test_btc_and_eth_mixed_formats_together():
    text = (
        "Legacy BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
        "Bech32 BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 "
        "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    )
    detections = extract(text)

    values = {d.value for d in detections}

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" in values
    assert "0x52908400098527886E0F7030069857D2E4169EE7" in values


def test_is_valid_btc_address_wrong_payload_length():
    # Construct a valid Base58Check payload with wrong length
    # Version byte = 0x00 (valid)
    # Payload = 1 byte instead of 20
    payload = b"\x00" + b"\x42" # only 2 bytes total

    # Compute checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    # Full bytes = payload + checksum
    full = payload + checksum

    # Convert to Base58
    num = int.from_bytes(full, "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = alphabet[rem] + encoded

    # Add leading '1' for each leading zero byte
    n_pad = len(full) - len(full.lstrip(b"\x00"))
    encoded = "1" * n_pad + encoded

    # Now encoded is a valid Base58Check string with wrong payload length
    assert is_valid_btc_address(encoded) is False
