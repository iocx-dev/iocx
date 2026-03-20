import pytest
from iocx.detectors.extractors.urls.strict_url import extract_strict_urls

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # Basic URL
    (
        "Visit http://example.com for details.",
        ["http://example.com"]
    ),

    # URL with path + query
    (
        "Go to https://malx.io/path?x=1&y=2",
        ["https://malx.io/path?x=1&y=2"]
    ),

    # IPv4 URL
    (
        "C2 at http://192.168.1.10:8080",
        ["http://192.168.1.10:8080"]
    ),

    # IPv6 URL
    (
        "Server https://[2001:db8::1]/index",
        ["https://[2001:db8::1]/index"]
    ),
])
def test_strict_url_positive(text, expected):
    out = extract_strict_urls(text)
    assert [d.value for d in out] == expected


# ------------------------------------------------------------
# NEGATIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text", [

    # Garbage that looks like a domain but is not a URL
    "This is not a URL: d.dp.",
])
def test_strict_url_negative(text):
    out = extract_strict_urls(text)
    assert [d.value for d in out] == []
