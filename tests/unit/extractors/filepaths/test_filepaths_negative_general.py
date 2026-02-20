import pytest
from iocx.extractors.filepaths import extract

@pytest.mark.parametrize("text", [
    "example.com",
    "d.dp",
    "sub.domain.co",
    "random text with no paths",
])
def test_no_false_positives(text):
    assert extract(text) == []
