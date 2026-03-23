import pytest
from iocx.detectors.extractors.urls.normalise import normalise_url


def test_normalise_basic():
    assert normalise_url("HTTP://Example.COM") == "http://example.com"


def test_normalise_trailing_dot():
    assert normalise_url("http://example.com.") == "http://example.com"


def test_normalise_bare_domain():
    assert normalise_url("Example.COM.") == "example.com"


def test_normalise_ipv6_with_port():
    assert normalise_url("http://[2001:db8::1]:443/path") == "http://[2001:db8::1]:443/path"


def test_normalise_ipv4_with_port():
    assert normalise_url("http://192.168.1.10:8080") == "http://192.168.1.10:8080"


def test_normalise_ipv6_without_port():
    assert normalise_url("http://[2001:db8::1]/x") == "http://[2001:db8::1]/x"


def test_normalise_ipv4_without_port():
    assert normalise_url("http://Example.COM/path") == "http://example.com/path"

def test_normalise_url_with_userinfo():
    result = normalise_url("http://user:pass@Example.com:8080/path")

    # Hostname lowercased, userinfo preserved
    assert result == "http://user:pass@example.com:8080/path"


def test_normalise_url_without_userinfo():
    result = normalise_url("http://Example.com/path")

    assert result == "http://example.com/path"
