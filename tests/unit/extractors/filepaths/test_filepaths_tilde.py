import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("~/bin/run.sh", ["/bin/run.sh", "~/bin/run.sh"]),
    ("~root/.ssh/id_rsa", ["~root/.ssh/id_rsa"]),
    ("prefix ~/scripts/tool suffix", ["/scripts/tool", "~/scripts/tool"]),
])
def test_tilde_matches(text, expected):
    assert extract(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("~", []),
    ("user~/.config", ["/.config"]),
])
def test_tilde_negative(text, expected):
    assert extract(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("user~/.config", ["/.config"]),  # UNIX abs now matches
])
def test_tilde_mid_token_rejected(text, expected):
    assert extract(text) == expected

# expansion only when subdirectories exist)
@pytest.mark.parametrize("text, expected", [
    ("~/bin/run.sh", ["/bin/run.sh", "~/bin/run.sh"]),
    ("~root/.ssh/id_rsa", ["~root/.ssh/id_rsa"]),
    ("prefix ~/scripts/tool suffix", ["/scripts/tool", "~/scripts/tool"]),
    ("~/.config/evil.sh", ["/.config/evil.sh", "~/.config/evil.sh"]),
    ("~/start", ["/start", "~/start"]),   # now expands
])
def test_tilde_valid(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text, expected", [
    ("~", []),
    ("~root", []),
    ("user~/.config", ["/.config"]),
    ("~!/.config", ["/.config"]),
    ("~@/file", ["/file"]),
    ("~$/tmp", ["/tmp"]),
])
def test_tilde_invalid(text, expected):
    assert extract(text) == expected

def test_tilde_multiple():
    text = "Use ~/one and ~/two/scripts"
    expected = [
        "/one",
        "/two/scripts",
        "~/one",
        "~/two/scripts",
    ]
    assert extract(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("~/start", ["/start", "~/start"]),
    ("end ~/finish", ["/finish", "~/finish"]),
])
def test_tilde_boundaries(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", ["~root", "~admin", "~bob"])
def test_tilde_user_no_slash(text):
    assert extract(text) == []

@pytest.mark.parametrize("text, expected", [
    ("~/.bashrc", ["~/.bashrc", "/.bashrc"]),
    ("~/.profile", ["~/.profile", "/.profile"]),
])
def test_tilde_hidden_files(text, expected):
    assert set(extract(text)) == set(expected)


