# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
import time
import random
import string
import idna

from iocx.detectors.extractors.urls.bare_domain import extract_bare_domains


# -----------------------------
# Random domain generators
# -----------------------------

ASCII_TLDS = ["com", "net", "org", "io", "co", "uk", "biz", "info"]

def rand_ascii_domain():
    """Generate a random valid ASCII domain."""
    name = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 15)))
    tld = random.choice(ASCII_TLDS)
    return f"{name}.{tld}"


def rand_punycode_ascii_only():
    """Valid punycode that decodes to ASCII only."""
    label = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 20)))
    return idna.encode(label).decode()


UNICODE_SAMPLES = [
    "á", "é", "í", "ó", "ú", "ñ", "ü",
    "ß", "ø", "å", "ç",
    "д", "ж", "я", "ю", "ф",
    "λ", "π", "σ", "ω",
    "漢", "字", "語",
]

def rand_punycode_unicode():
    """Valid punycode that decodes to Unicode."""
    prefix = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 15)))
    suffix = random.choice(UNICODE_SAMPLES)
    return idna.encode(prefix + suffix).decode()


def rand_homoglyph_noise(n=20):
    """Random Unicode noise including homoglyphs."""
    noise_chars = (
        "✪❖★☆✧✦" +
        "раура" + # Cyrillic homoglyphs
        "οο" # Greek omicron
    )
    return "".join(random.choice(noise_chars) for _ in range(n))


def random_ascii_noise(n=200):
    chars = string.ascii_letters + string.digits + ":./[]%_-"
    return "".join(random.choice(chars) for _ in range(n))


# -----------------------------
# Build large mixed input
# -----------------------------

def build_large_domain_input(size_kb=500):
    """Build ~size_kb KB of mixed ASCII, punycode, and Unicode noise."""
    generators = [
        rand_ascii_domain,
        rand_punycode_ascii_only,
        rand_punycode_unicode,
    ]

    chunks = []
    for _ in range(size_kb):
        r = random.random()
        if r < 0.33:
            chunks.append(" " + rand_ascii_domain() + " ")
        elif r < 0.66:
            chunks.append(" " + random.choice(generators)() + " ")
        else:
            # Unicode noise or ASCII noise
            if random.random() < 0.5:
                chunks.append(rand_homoglyph_noise(30))
            else:
                chunks.append(random_ascii_noise(50))

    return " ".join(chunks)


# -----------------------------
# Performance Tests
# -----------------------------

@pytest.mark.performance
def test_domains_large_input_performance():
    """Ensure domain extractor handles ~1MB mixed content quickly."""
    text = build_large_domain_input(1000) # ~1MB

    start = time.perf_counter()
    result = extract_bare_domains(text)
    duration = time.perf_counter() - start

    print(f"[perf] domains 1MB mixed-content: {duration:.4f}s")

    assert duration < 0.12, f"Domain extractor too slow: {duration:.3f}s"


@pytest.mark.performance
def test_domains_pathological_performance():
    """
    Stress-test punycode-like patterns without producing a valid domain.
    Ensures regex does not catastrophically backtrack.
    """

    # Three huge punycode-like labels, but NO final TLD → not a domain
    pathological = (
        "xn--" + ("a" * 5000) + "." +
        "xn--" + ("b" * 5000) + "." +
        "xn--" + ("c" * 5000) + "_"
    )

    start = time.perf_counter()
    result = extract_bare_domains(pathological)
    duration = time.perf_counter() - start
    print(result)
    print(f"[perf] pathological punycode-like blob: {duration:.4f}s")

    # Should be extremely fast (<30ms)
    assert duration < 0.03, f"Pathological input too slow: {duration:.3f}s"

    # No valid TLD → extractor must return nothing
    assert result == []


@pytest.mark.performance
def test_domains_scaling_behavior():
    """Ensure roughly linear scaling with input size."""

    # Warm-up run to stabilize regex engine
    extract_bare_domains(build_large_domain_input(200))

    sizes = [300, 600, 1000, 1500] # KB
    timings = []

    for size in sizes:
        text = build_large_domain_input(size)

        # median of 3 runs to reduce noise
        runs = []
        for _ in range(3):
            start = time.perf_counter()
            extract_bare_domains(text)
            runs.append(time.perf_counter() - start)

        duration = sorted(runs)[1] # median
        timings.append(duration)
        print(f"[perf] domains {size}KB: {duration:.4f}s")

    # Ensure no superlinear blow-up (allow 2.5× growth per doubling)
    for i in range(1, len(timings)):
        assert timings[i] < timings[i - 1] * 2.5, "Non-linear scaling detected"
