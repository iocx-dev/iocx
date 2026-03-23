import pytest
from iocx.detectors.extractors.urls import extract


def test_super_detector_combines_urls_and_domains():
    text = """
        hxxp://malx[.]io
        example.com
        https://test.org/path
    """
    result = extract(text)

    assert "urls" in result
    assert "domains" in result

    urls = [d.value for d in result["urls"]]
    domains = [d.value for d in result["domains"]]

    assert "http://malx.io" in urls
    assert "https://test.org/path" in urls
    assert "example.com" in domains


def test_super_detector_dedupes():
    text = "example.com example.com"
    result = extract(text)

    domains = [d.value for d in result["domains"]]

    # Deduplication expected
    assert domains == ["example.com"]
