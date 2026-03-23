import pytest
from iocx.detectors.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("%APPDATA%\\Microsoft\\Windows\\file.txt",
     ["%APPDATA%\\Microsoft\\Windows\\file.txt"]),

    ("$HOME/.config/tool",
     ["$HOME/.config/tool"]),
])
def test_env_paths_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [
    "$not valid/path",     # space breaks it
    "%BAD VAR%\\file",     # space in var name
])
def test_env_paths_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []

