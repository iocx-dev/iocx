import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    (".\\run", [".\\run"]),
    ("..\\bin\\tool", ["..\\bin\\tool"]),
    ("./run", ["./run"]),
    ("../bin/tool", ["../bin/tool"]),
    ("prefix ../scripts/build suffix", ["../scripts/build suffix"]),
])
def test_relative_matches(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", [
    ".",                # bare dot
    "..",               # bare double dot
    "abc./run",         # inside a word
    "foo../bar",        # malformed
])
def test_relative_negative(text):
    assert extract(text) == []
