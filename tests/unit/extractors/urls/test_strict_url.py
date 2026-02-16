import pytest
from iocx.extractors.urls.strict_url import extract_strict_urls


def test_strict_url_basic():
    text = "Visit http://example.com for details."
    assert extract_strict_urls(text) == ["http://example.com"]


def test_strict_url_with_path_and_query():
    text = "Go to https://malx.io/path?x=1&y=2"
    assert extract_strict_urls(text) == ["https://malx.io/path?x=1&y=2"]


def test_strict_url_ipv4():
    text = "C2 at http://192.168.1.10:8080"
    assert extract_strict_urls(text) == ["http://192.168.1.10:8080"]


def test_strict_url_ipv6():
    text = "Server https://[2001:db8::1]/index"
    assert extract_strict_urls(text) == ["https://[2001:db8::1]/index"]


def test_strict_url_does_not_match_garbage():
    text = "This is not a URL: d.dp."
    assert extract_strict_urls(text) == []
