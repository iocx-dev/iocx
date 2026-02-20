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
