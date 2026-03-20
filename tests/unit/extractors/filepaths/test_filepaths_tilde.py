import pytest
from iocx.detectors.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("~/bin/tool", ["/bin/tool", "~/bin/tool"]),
    ("~john/.ssh/id_rsa", ["~john/.ssh/id_rsa"]),
    ("~/path with space", ["~/path"]),
])
def test_tilde_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [
    "~",                     # too short
])
def test_tilde_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
