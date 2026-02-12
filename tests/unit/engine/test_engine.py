from malx_ioc_extractor.engine import extract_iocs

def test_extract_from_text():
    text = "Visit http://malx-labs.example"
    result = extract_iocs(text)
    assert "http://malx-labs.example" in result["iocs"]["urls"]
