# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.engine import Engine, EngineConfig
from iocx.detectors.registry import all_detectors

# Helper to run the single crypto detector
def run_crypto(data):
    detectors = all_detectors()
    fn = detectors["crypto"]
    return fn(data) # -> list[Detection]


# ------------------------------------------------------------
# 1. Core correctness
# ------------------------------------------------------------

def test_btc_simple():
    data = "Send BTC to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    detections = run_crypto(data)

    values = [d.value for d in detections]
    types = [d.category for d in detections]

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "crypto.btc" in types


def test_eth_simple():
    data = "ETH: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    detections = run_crypto(data)

    values = [d.value for d in detections]
    types = [d.category for d in detections]

    assert "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe" in values
    assert "crypto.eth" in types


# ------------------------------------------------------------
# 2. Noise tolerance
# ------------------------------------------------------------

def test_btc_with_noise():
    data = "random 1BoatSLRHtKNngkdXEeobR76b53LETtpyT junk"
    detections = run_crypto(data)
    assert any(d.value == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" for d in detections)


def test_eth_with_noise():
    data = "wallet=0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe; ok"
    detections = run_crypto(data)
    assert any(d.value == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe" for d in detections)


# ------------------------------------------------------------
# 3. False-positive resistance
# ------------------------------------------------------------

def test_btc_false_positive_short():
    data = "1BoatSLRHtKNngkdX"
    detections = run_crypto(data)
    assert detections == []


def test_eth_false_positive_missing_prefix():
    data = "de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    detections = run_crypto(data)
    assert detections == []


# ------------------------------------------------------------
# 4. Type isolation
# ------------------------------------------------------------

def test_btc_not_eth():
    data = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    detections = run_crypto(data)
    assert all(d.category == "crypto.btc" for d in detections)


def test_eth_not_btc():
    data = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    detections = run_crypto(data)
    assert all(d.category == "crypto.eth" for d in detections)


# ------------------------------------------------------------
# 5. Boundary cases
# ------------------------------------------------------------

def test_btc_min_length_valid():
    data = "1111111111111111111114oLvT2"
    detections = run_crypto(data)
    assert any(d.value == "1111111111111111111114oLvT2" for d in detections)


def test_eth_case_insensitive():
    data = "0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE"
    detections = run_crypto(data)
    assert any(d.value.lower() == data.lower() for d in detections)


# ------------------------------------------------------------
# 6. Pathological inputs
# ------------------------------------------------------------

def test_btc_pathological():
    data = "X" * 50000 + "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    detections = run_crypto(data)
    assert any(d.value == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" for d in detections)


def test_eth_pathological():
    data = "0x" + ("A" * 10000)
    detections = run_crypto(data)
    assert detections == []


# ------------------------------------------------------------
# 7. Mixed content
# ------------------------------------------------------------

def test_mixed_crypto():
    data = """
        btc=1BoatSLRHtKNngkdXEeobR76b53LETtpyT
        eth=0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe
    """
    detections = run_crypto(data)
    values = [d.value for d in detections]
    types = [d.category for d in detections]

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "crypto.btc" in types
    assert "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe" in values
    assert "crypto.eth" in types
