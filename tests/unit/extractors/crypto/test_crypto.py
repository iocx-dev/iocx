# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from iocx.detectors.extractors.crypto import extract
from iocx.models import Detection


def test_btc_valid_p2pkh():
    text = "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    detections = extract(text)
    values = [d.value for d in detections]
    types = [d.category for d in detections]
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in values
    assert "crypto.btc" in types


def test_btc_valid_p2sh():
    text = "Pay 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy now"
    detections = extract(text)
    assert any(
        d.value == "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_valid_bech32():
    text = "Deposit to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    detections = extract(text)
    assert any(
        d.value == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_valid_taproot():
    text = "Taproot: bc1p5cyxnuxmeuwuvkwfem96lxxss9p6l8k0k5l0f3"
    detections = extract(text)
    assert any(
        d.value == "bc1p5cyxnuxmeuwuvkwfem96lxxss9p6l8k0k5l0f3" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_invalid_checksum():
    text = "Fake BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpy"
    detections = extract(text)
    assert detections == []


def test_btc_case_sensitivity():
    text = (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "1a1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    detections = extract(text)
    assert any(
        d.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_near_miss():
    text = (
        "1KFHE7w8BhaENAswwryaoccDb6qcT6D " # too short
        "1O0Il123456789ABCDEFG " # invalid chars
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL" # missing last char
    )
    detections = extract(text)
    assert detections == []


def test_btc_noise_embedded():
    text = "xxx1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNayyy"
    detections = extract(text)
    assert detections == []


def test_btc_eth_mixed():
    text = (
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd "
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    detections = extract(text)
    assert any(
        d.value == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" and d.category == "crypto.eth"
        for d in detections
    )
    assert any(
        d.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_dedupe():
    text = (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    detections = extract(text)
    assert any(
        d.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" and d.category == "crypto.btc"
        for d in detections
    )


def test_btc_boundary():
    text = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa."
    detections = extract(text)
    assert any(
        d.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" and d.category == "crypto.btc"
        for d in detections
    )


def test_eth_detection():
    text = "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886E0F7030069857D2E4169EE7" and d.category == "crypto.eth"
        for d in detections
    )

def test_no_false_positives():
    text = "This is not a crypto address."
    detections = extract(text)

    assert detections == []
