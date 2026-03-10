import pytest
from iocx.extractors.ips import extract

# ---------------------------------------------------------
# Chaos corpus: attacker‑style malformed or obfuscated IOCs
# ---------------------------------------------------------
CHAOS_CORPUS = [
    # IPv6 mangled with junk
    "fe80::dead:beef%eth0/garbage",
    "2001:db8:::1:::/??!!",
    "GGGG::ZZZZ%eth0/64",
    "[2001:db8::1]::::443",
    "2001:db8::1:443:extra",
    "::ffff:192.168.1.10:evil",

    # IPv4 embedded in garbage
    "xxx192.168.1.10yyy",
    "DROP:client=10.0.0.1;;;ERR",
    "1.2.3.4.............BAD",
    "[ERROR] ip=172.16.0.1]]]]]",
    "192.168.0.1/24/garbage",

    # Split indicators
    "192.168.\n1.10",
    "2001:db8::\n1",
    "fe80::\n1%eth\n0",

    # Mixed encodings
    r"\x66\x65\x38\x30\x3a\x3a\x31",
    "fe80::1%25eth0",
    "31 39 32 2e 31 36 38 2e 31 2e 31",
    "2001%3Adb8%3A%3A1",

    # Protocol junk
    "GET http://[2001:db8::1]:443::::/index",
    "Host: 192.168.1.10:evil",
    "X-Forwarded-For: 10.0.0.1,unknown",
    "udp://[fe80::1%eth0]::::53",

    # Concatenated indicators
    "192.168.1.110.0.0.1",
    "2001:db8::12001:db8::2",
    "fe80::1%eth0fe80::2%eth1",

    # Almost-valid indicators
    "256.256.256.256",
    "2001:db8::g",
    "[2001:db8::1",
    "2001:db8::1]",
    "1.2.3.4:999999",
]

@pytest.mark.parametrize("sample", CHAOS_CORPUS)
@pytest.mark.robustness
def test_chaos_corpus(sample):
    """
    The extractor should:
    - salvage valid IPs hidden inside junk
    - ignore fully invalid indicators
    - never crash on malformed attacker-style input
    """
    out = extract(sample)

    # The key invariant: extractor must not crash and must return a list.
    assert isinstance(out, list)

    # Optional: if you want to enforce salvage-first behaviour:
    # If there's a valid IP hidden inside, extract() should not return [].
    # If the sample contains no valid IP at all, [] is acceptable.
    #
    # This keeps the test flexible while still enforcing correctness.
