from iocx.validators.dedupe import dedupe

def test_dedupe():
    data = {"urls": ["a", "a", "b"]}
    result = dedupe(data)
    assert result["urls"] == ["a", "b"]
