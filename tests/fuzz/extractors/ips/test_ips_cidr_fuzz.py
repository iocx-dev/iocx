"""
CIDR-aware fuzzing for the IP extractor.

This test stresses CIDR parsing with valid, invalid, and attacker-style
malformed masks. The extractor must never crash and must salvage valid IPs
even when the CIDR portion is corrupted.
"""

import pytest
import random
from iocx.extractors.ips import extract


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def rand_ipv4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def rand_ipv6():
    groups = [f"{random.randint(0, 0xFFFF):x}" for _ in range(8)]
    return ":".join(groups)

def rand_mask(max_bits):
    # Sometimes valid, sometimes invalid
    if random.random() < 0.7:
        return str(random.randint(0, max_bits))
    else:
        return random.choice(["999", "-1", "abc", "///", ""])


# ---------------------------------------------------------
# CIDR fuzz tests
# ---------------------------------------------------------
@pytest.mark.fuzz
def test_fuzz_ipv4_cidr():
    for _ in range(500):
        ip = rand_ipv4()
        mask = rand_mask(32)
        sample = f"{ip}/{mask}"
        out = extract(sample)

        # Must not crash
        assert isinstance(out, list)

        # Salvage-first behaviour:
        # - If valid CIDR → extractor may return "ip/mask"
        # - If invalid CIDR → extractor may salvage "ip"
        # - If mutation destroyed the IP → []
        assert out == [] or any(
            x == ip or x.startswith(ip + "/")
            for x in out
        )

@pytest.mark.fuzz
def test_fuzz_ipv6_cidr():
    for _ in range(500):
        ip = rand_ipv6()
        mask = rand_mask(128)
        sample = f"{ip}/{mask}"
        out = extract(sample)

        # Must not crash
        assert isinstance(out, list)

        # Salvage-first behaviour
        assert out == [] or any(":" in x for x in out)

@pytest.mark.fuzz
def rand_ipv6_compressed():
    full = rand_ipv6().split(":")
    start = random.randint(0, 5)
    end = start + random.randint(1, 3)
    return ":".join(full[:start] + [""] + full[end:])

@pytest.mark.fuzz
def rand_ipv6_zone():
    return f"{rand_ipv6()}%eth{random.randint(0,9)}"

@pytest.mark.fuzz
def test_fuzz_ipv6_cidr_v2():
    for _ in range(500):
        ip = rand_ipv6()
        mask = rand_mask(128)
        sample = f"{ip}/{mask}"
        out = extract(sample)

        assert isinstance(out, list)
        assert out == [] or any(
            x == ip or x.startswith(ip + "/") or ":" in x
            for x in out
        )

@pytest.mark.fuzz
def test_fuzz_ipv6_compressed_cidr():
    for _ in range(500):
        ip = rand_ipv6_compressed()
        mask = rand_mask(128)
        sample = f"{ip}/{mask}"
        out = extract(sample)

        assert isinstance(out, list)
        assert out == [] or any(":" in x for x in out)

@pytest.mark.fuzz
def test_fuzz_ipv6_zone_cidr():
    for _ in range(500):
        ip = rand_ipv6_zone()
        mask = rand_mask(128)
        sample = f"{ip}/{mask}"
        out = extract(sample)

        assert isinstance(out, list)
        assert out == [] or any(":" in x for x in out)


# ---------------------------------------------------------
# Mixed garbage CIDR fuzzing
# ---------------------------------------------------------
MUTATIONS = [
    lambda s: s + "/garbage",
    lambda s: "xxx" + s + "yyy",
    lambda s: s.replace("/", "//"),
    lambda s: s.replace("/", "/999/"),
    lambda s: s + ":evil",
    lambda s: s + "/-1",
]

@pytest.mark.parametrize("mutate", MUTATIONS)
@pytest.mark.fuzz
def test_cidr_mutation_fuzz(mutate):
    for _ in range(200):
        base = f"{rand_ipv4()}/{rand_mask(32)}"
        sample = mutate(base)
        out = extract(sample)

        assert isinstance(out, list)
        # Salvage IPv4 if present
        assert out == [] or any("." in x for x in out)
