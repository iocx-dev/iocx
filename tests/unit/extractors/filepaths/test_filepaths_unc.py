import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("\\\\SERVER01\\share\\dropper.exe", ["\\\\SERVER01\\share\\dropper.exe"]),
    ("\\\\192.168.1.44\\c$\\Windows\\Temp\\run.ps1",
     ["\\\\192.168.1.44\\c$\\Windows\\Temp\\run.ps1"]),
])
def test_unc_matches(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", [
    "\\\\bad path",      # space not allowed
    "\\\\server",        # missing share
])
def test_unc_negative(text):
    assert extract(text) == []
