import pytest
from iocx.detectors.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("./run.sh", ["./run.sh"]),
    ("../bin/tool", ["../bin/tool"]),
    ("./path with space/a", ["./path with space/a"]),
])
def test_relative_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [
    "temp/run",           # ambiguous
    "../",
])
def test_relative_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []

