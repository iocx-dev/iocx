import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("/usr/bin/python", ["/usr/bin/python"]),
    ("/bin/sh", ["/bin/sh"]),
    ("prefix /opt/app/run suffix", ["/opt/app/run"]),
])
def test_unix_abs_matches(text, expected):
    assert extract(text) == expected

@pytest.mark.parametrize("text", [
    "usr/bin/python",     # missing leading slash
    "/justslash/",        # ends with slash only
])
def test_unix_abs_negative(text):
    assert extract(text) == []

@pytest.mark.parametrize("text", [
    "/etc"
])
def test_unix_single_segment_not_rejected(text):
    assert extract(text) == ["/etc"]

@pytest.mark.parametrize("text", [
    "/opt/app/run suffix"
])
def test_unix_suffix_rejected(text):
    assert extract(text) == ["/opt/app/run"]
