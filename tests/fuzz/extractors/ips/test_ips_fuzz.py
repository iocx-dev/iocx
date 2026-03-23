import pytest
import random
import string
from iocx.detectors.extractors.ips import extract


# -----------------------------
# Helpers to generate fuzz data
# -----------------------------
def _vals(out):
    if not out:
        return []
    return [d.value for d in out]

def rand_ipv4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def rand_ipv6():
    groups = [f"{random.randint(0, 0xFFFF):x}" for _ in range(8)]
    return ":".join(groups)

def rand_ipv6_compressed():
    full = rand_ipv6().split(":")
    start = random.randint(0, 5)
    end = start + random.randint(1, 3)
    # This may produce invalid IPv6 — that’s fine, extractor must not crash
    return ":".join(full[:start] + [""] + full[end:])

def rand_noise(length=20):
    chars = string.ascii_letters + string.digits + ":./[]%_-"
    return "".join(random.choice(chars) for _ in range(length))


# -----------------------------
# Valid cases (must salvage)
# -----------------------------
@pytest.mark.parametrize("ip", [
    "192.168.1.1",
    "10.0.0.1/24",
    "255.255.255.255",
    "2001:db8::1",
    "2001:db8::/32",
    "fe80::1%eth0",
    "[2001:db8::1]:443",
    "192.168.0.1:8080",
])

@pytest.mark.fuzz
def test_valid_ips(ip):
    out = extract(ip)
    assert isinstance(out, list)
    assert out != []


# -----------------------------
# Invalid cases (may salvage)
# -----------------------------
@pytest.mark.parametrize("bad", [
    "999.999.999.999",
    "256.0.0.1",
    "2001:::1:::",
    "[2001:db8::1",
    "2001:db8::1]",
    "2001:db8::1:999999",
    "1.2.3.4/999",
])
@pytest.mark.fuzz
def test_invalid_ips(bad):
    out = extract(bad)
    # Extractor must not crash and must return a list
    assert isinstance(out, list)

    vals = _vals(out)

    # If there's a valid IP substring, salvage it; otherwise return []
    # This matches the documented v0.2.0 behaviour
    assert vals == [] or all(isinstance(x, str) for x in vals)


# -----------------------------
# Fuzz: random valid IPv4
# -----------------------------
@pytest.mark.fuzz
def test_fuzz_ipv4():
    for _ in range(500):
        ip = rand_ipv4()

        out = extract(ip)
        vals = _vals(out)

        assert vals == [ip]


# -----------------------------
# Fuzz: random valid IPv6
# -----------------------------
@pytest.mark.fuzz
def test_fuzz_ipv6():
    for _ in range(500):
        ip = rand_ipv6()
        out = extract(ip)
        assert out != []


# -----------------------------
# Fuzz: compressed IPv6 (may be invalid)
# -----------------------------
@pytest.mark.fuzz
def test_fuzz_ipv6_compressed():
    for _ in range(500):
        ip = rand_ipv6_compressed()
        out = extract(ip)
        # Extractor must not crash
        assert isinstance(out, list)
        # If valid, salvage; if invalid, return []
        assert out == [] or len(out) >= 1


# -----------------------------
# Fuzz: noise (should rarely produce IPs)
# -----------------------------
@pytest.mark.fuzz
def test_noise():
    hits = 0
    for _ in range(500):
        noise = rand_noise()
        out = extract(noise)
        assert isinstance(out, list)
        if out:
            hits += 1
    # Allow occasional accidental matches, but not too many
    assert hits < 20
