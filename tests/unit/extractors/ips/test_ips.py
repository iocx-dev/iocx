import pytest
from iocx.extractors.ips import extract


# ------------------------------------------------------------
# IPv4 BASIC CASES
# ------------------------------------------------------------

def test_basic_ipv4():
    text = "Connect to 1.2.3.4 immediately"
    assert extract(text) == ["1.2.3.4"]


def test_multiple_ipv4():
    text = "IPs: 8.8.8.8 and 1.1.1.1"
    assert extract(text) == ["8.8.8.8", "1.1.1.1"]


def test_ipv4_with_punctuation():
    text = "Server at 10.0.0.1,"
    assert extract(text) == ["10.0.0.1"]


def test_ipv4_inside_url():
    text = "http://192.168.0.1/login"
    assert extract(text) == ["192.168.0.1"]


def test_ipv4_invalid_but_matched():
    text = "999.999.999.999"
    assert extract(text) == []

def test_ip_with_port_invalid():
    text = "Connect: 1.2.3.999:80"
    assert extract(text) == []


# ------------------------------------------------------------
# IPv6 BASIC CASES
# ------------------------------------------------------------

def test_basic_ipv6():
    text = "Connect to fe80::1"
    assert extract(text) == ["fe80::1"]


def test_ipv6_uppercase():
    text = "Address: FE80::ABCD:1234"
    assert extract(text) == ["FE80::ABCD:1234"]


def test_ipv6_with_multiple_colons():
    text = "Route to 2001:0db8:85a3::8a2e:0370:7334"
    assert extract(text) == ["2001:0db8:85a3::8a2e:0370:7334"]


def test_ipv6_inside_url():
    text = "http://[2001:db8::1]/index.html"
    assert extract(text) == ["2001:db8::1"]


# ------------------------------------------------------------
# IPv6 ZONE INDICES
# ------------------------------------------------------------

def test_ipv6_zone_index():
    text = "Link-local: fe80::1%eth0"
    assert extract(text) == ["fe80::1%eth0"]

def test_ipv6_zone_invalid():
    text = "Bad zone: fe80::1%"
    # fe80::1 is still a valid IPv6, so it should be extracted
    assert extract(text) == ["fe80::1"]

def test_ipv6_zone_with_cidr_rejected():
    text = "Bad: fe80::1%eth0/64"
    # Treated as a network, not a zone-indexed IPv6
    assert extract(text) == ["fe80::1%eth0/64"]

def test_ipv6_zone_with_cidr_rejected_v2():
    text = "Bad: fe80::GGGG%eth0/64"
    assert extract(text) == ["fe80::"]

def test_ipv6_zone_with_cidr_rejected_v3():
    text = "Bad: GGGG::ZZZZ%eth0/64"
    assert extract(text) == ["::"]

def test_ipv6_zone_invalid_addr_hits_except():
    text = "Bad: GGGG%eth0"
    assert extract(text) == []


# ------------------------------------------------------------
# Bracketed IPv6 invalid address
# ------------------------------------------------------------

def test_bracketed_ipv6_invalid():
    text = "Address: [GGGG::1]"
    # ::1 is a valid IPv6 suffix, so it will be extracted
    assert extract(text) == ["::1"]


# ------------------------------------------------------------
# Bracketed IPv6 invalid port
# ------------------------------------------------------------

def test_bracketed_ipv6_invalid_port():
    text = "Address: [2001:db8::1]:99999"
    assert extract(text) == []

def test_bracketed_ipv6_port_out_of_range():
    text = "Address: [2001:db8::1]:70000"
    assert extract(text) == []  # port invalid → reject whole token

def test_bracketed_ipv6_port_out_of_range_v2():
    text = "Address: [2001:db8::1]:99999"
    assert extract(text) == []

def test_bracketed_ipv6_port_out_of_range_hits_invalid_port_branch():
    text = "[2001:db8::1]:70000"
    assert extract(text) == []


# ------------------------------------------------------------
# Bracketed IPv6 regex mismatch
# ------------------------------------------------------------

def test_bracketed_ipv6_regex_mismatch():
    text = "Weird: [::::]"
    assert extract(text) == []  # nothing valid inside


# ------------------------------------------------------------
# MIXED CASES
# ------------------------------------------------------------

def test_ipv4_and_ipv6_together():
    text = "IPv4: 1.2.3.4 IPv6: fe80::1"
    assert extract(text) == ["1.2.3.4", "fe80::1"]


def test_no_false_positives():
    text = "Not an IP: 300.300.300"
    assert extract(text) == []


# ------------------------------------------------------------
# NETWORKS
# ------------------------------------------------------------

def test_ipv4_network_valid():
    text = "Network: 192.168.0.0/24"
    assert extract(text) == ["192.168.0.0/24"]

def test_ipv4_network_invalid():
    text = "Invalid: 192.168.0.999/24"
    assert extract(text) == []


# ------------------------------------------------------------
# TOKEN CACHING
# ------------------------------------------------------------

def test_caching_repeated_tokens():
    text = "IP 1.2.3.4 appears twice: 1.2.3.4"
    assert extract(text) == ["1.2.3.4", "1.2.3.4"]
