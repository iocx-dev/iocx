import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    (
        "C:\\Windows\\System32\\cmd.exe",
        ["C:\\Windows\\System32\\cmd.exe"]
    ),

    # Windows absolute path + Unix absolute path
    (
        "prefix C:/Users/Admin/run.bat suffix",
        ["C:/Users/Admin/run.bat suffix", "/Users/Admin/run.bat"]
    ),
])
def test_windows_abs_matches(text, expected):
    assert extract(text) == expected


@pytest.mark.parametrize("text", [
    "C:folder\\file.exe",   # missing slash after drive letter
])
def test_windows_abs_negative(text):
    assert extract(text) == []
