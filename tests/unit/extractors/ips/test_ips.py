import pytest
from iocx.detectors.extractors.ips import extract

@pytest.mark.parametrize("text, expected", [

    # IPv4 BASIC
    ("Connect to 1.2.3.4 immediately",
     ["1.2.3.4"]),

    ("IPs: 8.8.8.8 and 1.1.1.1",
     ["8.8.8.8", "1.1.1.1"]),

    ("Server at 10.0.0.1,",
     ["10.0.0.1"]),

    ("http://192.168.0.1/login",
     ["192.168.0.1"]),

    # IPv6 BASIC
    ("Connect to fe80::1",
     ["fe80::1"]),

    ("Address: FE80::ABCD:1234",
     ["FE80::ABCD:1234"]),

    ("Route to 2001:0db8:85a3::8a2e:0370:7334",
     ["2001:0db8:85a3::8a2e:0370:7334"]),

    ("http://[2001:db8::1]/index.html",
     ["2001:db8::1"]),

    # IPv6 ZONE INDICES
    ("Link-local: fe80::1%eth0",
     ["fe80::1%eth0"]),

    ("Bad zone: fe80::1%",
     ["fe80::1"]),

    ("Bad: fe80::1%eth0/64",
     ["fe80::1%eth0/64"]),

    ("Bad: fe80::GGGG%eth0/64",
     ["fe80::"]),

    ("Bad: GGGG::ZZZZ%eth0/64",
     ["::"]),

    # Bracketed IPv6 invalid address
    ("Address: [GGGG::1]",
     ["::1"]),

    # Mixed IPv4 + IPv6
    ("IPv4: 1.2.3.4 IPv6: fe80::1",
     ["1.2.3.4", "fe80::1"]),

    # Networks
    ("Network: 192.168.0.0/24",
     ["192.168.0.0/24"]),

    # Token caching
    ("IP 1.2.3.4 appears twice: 1.2.3.4",
     ["1.2.3.4", "1.2.3.4"]),
])
def test_ip_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected

@pytest.mark.parametrize("text", [

    # IPv4 invalid
    "999.999.999.999",
    "Connect: 1.2.3.999:80",

    # IPv6 invalid zone
    "Bad: GGGG%eth0",

    # Bracketed IPv6 invalid port
    "Address: [2001:db8::1]:99999",
    "Address: [2001:db8::1]:70000",
    "[2001:db8::1]:70000",

    # Bracketed IPv6 regex mismatch
    "Weird: [::::]",

    # No false positives
    "Not an IP: 300.300.300",

    # IPv4 network invalid
    "Invalid: 192.168.0.999/24",
])
def test_ip_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
