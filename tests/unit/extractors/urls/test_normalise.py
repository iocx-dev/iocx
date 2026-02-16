import pytest
from iocx.extractors.urls.normalise import normalise_url


def test_normalise_basic():
    assert normalise_url("HTTP://Example.COM") == "http://example.com"


def test_normalise_trailing_dot():
    assert normalise_url("http://example.com.") == "http://example.com"


def test_normalise_bare_domain():
    assert normalise_url("Example.COM.") == "example.com"
