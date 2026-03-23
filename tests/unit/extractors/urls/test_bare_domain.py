import pytest
from iocx.detectors.extractors.urls.bare_domain import extract_bare_domains

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # Basic valid domains
    ("example.com", ["example.com"]),
    ("sub.domain.co.uk", ["sub.domain.co.uk"]),
    ("foo.bar", ["foo.bar"]),
    ("my-site123.net", ["my-site123.net"]),

    # Multiple domains
    ("visit example.com and test.org", ["example.com", "test.org"]),
    ("a.com b.net c.io", ["a.com", "b.net", "c.io"]),

    # Boundaries
    ("(example.com)", ["example.com"]),
    ("[test.org]", ["test.org"]),
    ("prefix example.com suffix", ["example.com"]),

    # Punycode
    ("xn--d1acufc.xn--p1ai", ["xn--d1acufc.xn--p1ai"]),
    ("prefix xn--example-9d0b.com suffix", ["xn--example-9d0b.com"]),

    # Mixed content
    ("example.com /usr/bin/python test.org", ["example.com", "test.org"]),
    ("cmd.exe example.com foo.dll", ["example.com"]),
])
def test_bare_domain_positive(text, expected):
    out = extract_bare_domains(text)
    assert [d.value for d in out] == expected


# ------------------------------------------------------------
# NEGATIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text", [

    # Should NOT match file extensions
    "cmd.exe",
    "kernel32.dll",
    "data.sys",
    "startup.text",
    "foo.pdata",
    "bar.xdata",
    "baz.rdata",

    # Should NOT match inside filepaths
    r"C:\Windows\System32\cmd.exe",
    "/usr/bin/python",
    "/opt/app/run.sh",
    "../scripts/build",

    # Should NOT match inside emails
    "user@example.com",
    "admin@test.org",
    "contact@foo.bar",

    # Should NOT match dotted junk
    "a.b.c.d.e",
    "foo..bar",
    ".hidden.domain",
    "domain.",

    # Should NOT match inside words
    "notadomainexample.comtext",
    "prefixexample.comsuffix",

    # Should NOT match fake TLDs
    "foo.zzz",
    "bar.qwerty",
])
def test_bare_domain_negative(text):
    out = extract_bare_domains(text)
    assert [d.value for d in out] == []
