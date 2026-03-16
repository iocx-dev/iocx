import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("~/bin/run.sh", ["/bin/run.sh", "~/bin/run.sh"]),
    ("~root/.ssh/id_rsa", ["~root/.ssh/id_rsa"]),
    ("prefix ~/scripts/tool suffix", ["/scripts/tool", "~/scripts/tool"]),
])
def test_tilde_matches(text, expected):
    assert extract(text) == expected


@pytest.mark.parametrize("text", [
    "~",                # bare tilde
    "user~/.config",    # inside a word
])
def test_tilde_negative(text):
    assert extract(text) == []

@pytest.mark.parametrize("text", [
    "user~/.config"
])
def test_tilde_mid_token_rejected(text):
    assert extract(text) == []

# expansion only when subdirectories exist)
@pytest.mark.parametrize("text, expected", [
    ("~/bin/run.sh", ["/bin/run.sh", "~/bin/run.sh"]),
    ("~root/.ssh/id_rsa", ["~root/.ssh/id_rsa"]),
    ("prefix ~/scripts/tool suffix", ["/scripts/tool", "~/scripts/tool"]),
    ("~/.config/evil.sh", ["/.config/evil.sh", "~/.config/evil.sh"]),
    ("~/start", ["~/start"]),          # no expansion
])
def test_tilde_valid(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", [
    "~",                # bare tilde
    "~root",            # no path segment
    "user~/.config",    # mid-token
    "~!/.config",       # invalid username
    "~@/file",
    "~$/tmp",
])
def test_tilde_invalid(text):
    assert extract(text) == []

def test_tilde_multiple():
    text = "Use ~/one and ~/two/scripts"
    expected = [
        "/two/scripts",
        "~/one",
        "~/two/scripts",
    ]
    assert extract(text) == expected

@pytest.mark.parametrize("text, expected", [
    ("~/start", ["~/start"]),                 # no expansion
    ("end ~/finish", ["~/finish"]),           # no expansion
])
def test_tilde_boundaries(text, expected):
    assert extract(text) == expected
