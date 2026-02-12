from malx_ioc_extractor.parsers.string_extractor import extract_strings

def test_extract_strings(tmp_path):
    f = tmp_path / "bin.bin"
    f.write_bytes(b"hello\x00world")

    strings = extract_strings(str(f))
    assert "hello" in strings
    assert "world" in strings
