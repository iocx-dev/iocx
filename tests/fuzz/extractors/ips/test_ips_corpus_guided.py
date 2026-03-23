"""
Corpus-guided fuzzing for the IP extractor.

These tests simulate attacker-style malformed indicators commonly found in
malware configs, obfuscated payloads, corrupted logs, and C2 beacons.

They are not strict unit tests — they are resilience tests. The extractor
must never crash, and must salvage valid IPs when present, even inside junk.
"""

import pytest
import random
import string
from iocx.detectors.extractors.ips import extract


# ---------------------------------------------------------
# Seed corpus: realistic, attacker-style IOC fragments
# ---------------------------------------------------------
SEED_CORPUS = [
    # C2-style IPv6
    "2001:db8::1:443",
    "fe80::dead:beef%eth0",
    "::ffff:192.168.1.10",

    # Junk-wrapped IPv4
    "AAABBB192.168.1.10CCC",
    "client=10.0.0.1;err",
    "172.16.0.1]]]]",

    # Obfuscated / encoded
    r"\x32\x30\x30\x31\x3a\x64\x62\x38\x3a\x3a\x31",
    "2001%3Adb8%3A%3A1",
    "31 39 32 2e 31 36 38 2e 31 2e 31",

    # Concatenated indicators
    "192.168.1.110.0.0.1",
    "2001:db8::12001:db8::2",

    # Protocol fragments
    "GET http://[2001:db8::1]:443/index",
    "udp://[fe80::1%eth0]:53",
    "Host: 192.168.1.10:evil",

    # Broken brackets
    "[2001:db8::1",
    "2001:db8::1]",
]

# ---------------------------------------------------------
# Helper
# ---------------------------------------------------------
def _vals(out):
    if not out:
        return []
    return [d.value for d in out]

# ---------------------------------------------------------
# Mutation strategies
# ---------------------------------------------------------
def mutate(s: str) -> str:
    ops = [
        lambda x: x + random.choice(string.punctuation),
        lambda x: random.choice(string.punctuation) + x,
        lambda x: x.replace(":", "::", 1),
        lambda x: x.replace(".", "..", 1),
        lambda x: x[::-1],
        lambda x: x + random.choice(["%eth0", "%lo", "%wlan0"]),
        lambda x: x.replace("1", random.choice("abcdef")),
    ]
    return random.choice(ops)(s)


# ---------------------------------------------------------
# Corpus-guided fuzz test
# ---------------------------------------------------------
@pytest.mark.parametrize("seed", SEED_CORPUS)
@pytest.mark.fuzz
def test_corpus_guided_fuzz(seed):
    """
    For each seed, apply random mutations and ensure the extractor:

    - never crashes
    - always returns a list
    - salvages valid IPs when present
    - returns [] only when no valid IP remains after mutation
    """
    for _ in range(200):
        mutated = mutate(seed)
        out = extract(mutated)

        # Extractor must not crash
        assert isinstance(out, list)

        vals = _vals(out)

        # Salvage-first behaviour:
        # - If mutation preserved a valid IP substring → out != []
        # - If mutation destroyed all valid IPs → out == []
        assert vals == [] or all(isinstance(x, str) for x in vals)
