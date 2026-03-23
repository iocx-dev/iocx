import pytest
from iocx.detectors.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("\\\\server\\share\\folder\\file.txt",
     ["\\\\server\\share\\folder\\file.txt"]),
])
def test_unc_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [
    "\\server\\share\\file.txt",   # missing leading slash
    "\\\\server",                  # incomplete
    "\\\\server\\share\\bad|name", # illegal char
])
def test_unc_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
