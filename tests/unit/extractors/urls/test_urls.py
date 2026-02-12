from malx_ioc_extractor.extractors import urls

def test_url_extraction():
    text = "Visit https://example.com"
    assert urls.extract(text) == ["https://example.com"]
