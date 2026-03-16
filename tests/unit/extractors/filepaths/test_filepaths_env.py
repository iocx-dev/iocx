import pytest
from iocx.extractors.filepaths import extract

# ----------------------------------------------------------------------
# ENV paths that MUST match
# ----------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
     ["%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"]),
    ("$HOME/.config/evil.sh", ["$HOME/.config/evil.sh"]),
    ("$HOME", ["$HOME"]),                         # now valid
    ("%APPDATA%", ["%APPDATA%"]),                 # now valid
    ("$XDG_CONFIG_HOME", ["$XDG_CONFIG_HOME"]),   # now valid
])
def test_env_matches(text, expected):
    assert extract(text) == expected


# ----------------------------------------------------------------------
# ENV paths that should NOT match
# ----------------------------------------------------------------------
@pytest.mark.parametrize("text, expected", [
    ("%NOTCLOSED\\path.exe", []),      # malformed: missing closing %
    ("$not valid/path", ["$not"]),     # valid env var name, should match
])
def test_env_negative(text, expected):
    assert extract(text) == expected


# ----------------------------------------------------------------------
# Directory-only ENV paths (Unix)
# ----------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("$HOME/.config", ["$HOME/.config"]),
    ("$HOME/Documents", ["$HOME/Documents"]),
    ("$XDG_CONFIG_HOME", ["$XDG_CONFIG_HOME"]),
    ("$HOME", ["$HOME"]),   # now valid
])
def test_env_unix_directory_only(text, expected):
    assert extract(text) == expected
