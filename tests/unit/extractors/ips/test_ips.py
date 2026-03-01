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
    assert extract(text) == ["999.999.999.999"]


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
# MIXED CASES
# ------------------------------------------------------------

def test_ipv4_and_ipv6_together():
    text = "IPv4: 1.2.3.4 IPv6: fe80::1"
    assert extract(text) == ["1.2.3.4", "fe80::1"]


def test_no_false_positives():
    text = "Not an IP: 300.300.300"
    assert extract(text) == []
