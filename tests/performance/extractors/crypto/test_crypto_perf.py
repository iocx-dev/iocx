import pytest
import time
import random
import string
from iocx.detectors.extractors.crypto import extract


# -----------------------------
# Random crypto generators
# -----------------------------

def rand_btc():
    # Valid BTC P2PKH addresses start with '1' and are Base58
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    body = "".join(random.choices(alphabet, k=33))
    return "1" + body


def rand_eth():
    # Valid ETH address: 0x + 40 hex chars
    hexchars = "0123456789abcdef"
    body = "".join(random.choices(hexchars, k=40))
    return "0x" + body


def random_noise(n=200):
    chars = string.ascii_letters + string.digits + ":./[]%_-"
    return "".join(random.choice(chars) for _ in range(n))


# -----------------------------
# Build large mixed input
# -----------------------------

def build_large_crypto_input(size_kb=500):
    generators = [rand_btc, rand_eth]
    chunks = []
    for _ in range(size_kb):
        if random.random() < 0.5:
            # Insert BTC/ETH with safe boundaries
            chunks.append(" " + random.choice(generators)() + " ")
        else:
            chunks.append(random_noise(50))
    return " ".join(chunks)


# -----------------------------
# Performance Tests
# -----------------------------

@pytest.mark.performance
def test_crypto_large_input_performance():
    """Ensure crypto extractor handles ~1MB mixed content quickly."""
    text = build_large_crypto_input(1000) # ~1MB

    start = time.perf_counter()
    result = extract(text)
    duration = time.perf_counter() - start

    print(f"[perf] crypto 1MB mixed-content: {duration:.4f}s")

    # Crypto regexes are lightweight; < 50ms is a safe upper bound
    assert duration < 0.05, f"Crypto extractor too slow: {duration:.3f}s"


@pytest.mark.performance
def test_crypto_pathological_performance():
    """
    Worst-case for regex engines:
    - long hex-like sequences (ETH-like)
    - repeated separators
    - deep repetition
    """
    # Giant hex blob that *could* trigger backtracking in bad regexes
    pathological = "0x" + ("A" * 50000)

    start = time.perf_counter()
    result = extract(pathological)
    duration = time.perf_counter() - start

    print(f"[perf] pathological ETH-like blob: {duration:.4f}s")

    assert duration < 0.02, f"Pathological input too slow: {duration:.3f}s"
    assert result == []


@pytest.mark.performance
def test_crypto_scaling_behavior():
    """Ensure roughly linear scaling with input size."""

    # Warm-up run to stabilize regex engine
    extract(build_large_crypto_input(200))

    sizes = [300, 600, 1000, 1500] # KB
    timings = []

    for size in sizes:
        text = build_large_crypto_input(size)

        # median of 3 runs to reduce noise
        runs = []
        for _ in range(3):
            start = time.perf_counter()
            extract(text)
            runs.append(time.perf_counter() - start)

        duration = sorted(runs)[1] # median
        timings.append(duration)
        print(f"[perf] crypto {size}KB: {duration:.4f}s")

    # Ensure no superlinear blow-up (allow 2.5× growth per doubling)
    for i in range(1, len(timings)):
        assert timings[i] < timings[i-1] * 2.5, "Non-linear scaling detected"
