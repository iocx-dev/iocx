import pytest
from iocx.extractors.urls import extract


def test_super_detector_combines_urls_and_domains():
    text = """
        hxxp://malx[.]io
        example.com
        https://test.org/path
    """
    result = extract(text)

    assert "urls" in result
    assert "domains" in result

    assert "http://malx.io" in result["urls"]
    assert "https://test.org/path" in result["urls"]
    assert "example.com" in result["domains"]


def test_super_detector_dedupes():
    text = "example.com example.com"
    result = extract(text)
    assert result["domains"] == ["example.com"]
