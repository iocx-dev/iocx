import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("C:\\Windows\\System32\\cmd.exe",
     ["C:\\Windows\\System32\\cmd.exe"]),

    ("C:/Program Files/Windows Defender/mpcmdrun.exe",
     ["C:/Program Files/Windows Defender/mpcmdrun.exe"]),

    ("C:\\Users\\John Doe\\file.txt",
     ["C:\\Users\\John Doe\\file.txt"]),

    ("C:\\Users\\Public\\README",
     ["C:\\Users\\Public\\README"]),

    ("C:\\path\\with\nnewline.txt",
     ["C:\\path\\with"]),
])
def test_windows_abs_positive(text, expected):
    out = extract(text)
    values = [d.value for d in out]
    assert values == expected


@pytest.mark.parametrize("text", [
    "C:folder\\file.exe",          # missing slash after drive
    "C:\\Invalid|Name\\file.txt",  # illegal char
    "C:\\",                        # too short
])
def test_windows_abs_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
