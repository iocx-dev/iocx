import pytest
from iocx.detectors.extractors.crypto import extract

@pytest.mark.robustness
def test_crypto_empty_input():
    out = extract("")
    assert out == []

@pytest.mark.robustness
def test_crypto_whitespace_only():
    out = extract(" \n\t ")
    assert out == []

@pytest.mark.robustness
def test_crypto_unicode_noise():
    data = "💥💥💥 1BoatSLRHtKNngkdXEeobR76b53LETtpyT 💥💥💥"
    out = extract(data)
    values = [d.value for d in out]
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values

@pytest.mark.robustness
def test_crypto_pathological_repetition():
    data = "X" * 50000
    out = extract(data)
    assert out == []

@pytest.mark.robustness
def test_crypto_eth_boundary_safety():
    eth = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    data = f"A {eth} Z" # safe boundaries
    out = extract(data)
    values = [d.value.lower() for d in out]
    assert eth.lower() in values

@pytest.mark.robustness
def test_crypto_invalid_eth_missing_prefix():
    data = "de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    out = extract(data)
    assert out == []

@pytest.mark.robustness
def test_crypto_invalid_btc_short():
    data = "1BoatSLRHtKNngkdX"
    out = extract(data)
    assert out == []
