import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
     ["%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"]),
    ("$HOME/.config/evil.sh", ["$HOME/.config/evil.sh"]),
])
def test_env_matches(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", [
    "%NOTCLOSED\\path.exe",   # malformed
    "$HOME",                  # no path
])
def test_env_negative(text):
    assert extract(text) == []
