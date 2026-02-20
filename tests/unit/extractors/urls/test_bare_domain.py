import pytest
from iocx.extractors.urls.bare_domain import extract_bare_domains

#
# 1. Basic valid domains
#

@pytest.mark.parametrize("text, expected", [
    ("example.com", ["example.com"]),
    ("sub.domain.co.uk", ["sub.domain.co.uk"]),
    ("foo.bar", ["foo.bar"]),
    ("my-site123.net", ["my-site123.net"]),
])
def test_basic_domains(text, expected):
    assert extract_bare_domains(text) == expected


#
# 2. Multiple domains in one string
#

@pytest.mark.parametrize("text, expected", [
    ("visit example.com and test.org", ["example.com", "test.org"]),
    ("a.com b.net c.io", ["a.com", "b.net", "c.io"]),
])
def test_multiple_domains(text, expected):
    assert extract_bare_domains(text) == expected


#
# 3. Domains with boundaries
#

@pytest.mark.parametrize("text, expected", [
    ("(example.com)", ["example.com"]),
    ("[test.org]", ["test.org"]),
    ("prefix example.com suffix", ["example.com"]),
])
def test_domain_boundaries(text, expected):
    assert extract_bare_domains(text) == expected


#
# 4. Punycode domains
#

@pytest.mark.parametrize("text, expected", [
    ("xn--d1acufc.xn--p1ai", ["xn--d1acufc.xn--p1ai"]),
    ("prefix xn--example-9d0b.com suffix", ["xn--example-9d0b.com"]),
])
def test_punycode_domains(text, expected):
    assert extract_bare_domains(text) == expected


#
# 5. Should NOT match file extensions
#

@pytest.mark.parametrize("text", [
    "cmd.exe",
    "kernel32.dll",
    "data.sys",
    "startup.text",
    "foo.pdata",
    "bar.xdata",
    "baz.rdata",
])
def test_no_file_extensions(text):
    assert extract_bare_domains(text) == []


#
# 6. Should NOT match inside filepaths
#

@pytest.mark.parametrize("text", [
    r"C:\Windows\System32\cmd.exe",
    "/usr/bin/python",
    "/opt/app/run.sh",
    "../scripts/build",
])
def test_no_filepaths(text):
    assert extract_bare_domains(text) == []


#
# 7. Should NOT match inside emails
#

@pytest.mark.parametrize("text", [
    "user@example.com",
    "admin@test.org",
    "contact@foo.bar",
])
def test_no_emails(text):
    assert extract_bare_domains(text) == []


#
# 8. Should NOT match dotted junk
#

@pytest.mark.parametrize("text", [
    "a.b.c.d.e",
    "foo..bar",
    ".hidden.domain",
    "domain.",
])
def test_no_dotted_junk(text):
    assert extract_bare_domains(text) == []


#
# 9. Should NOT match inside words
#

@pytest.mark.parametrize("text", [
    "notadomainexample.comtext",
    "prefixexample.comsuffix",
    "abcexample.com",
])
def test_no_inside_words(text):
    assert extract_bare_domains(text) == []


#
# 10. Should NOT match TLD-like garbage
#

@pytest.mark.parametrize("text", [
    "foo.zzz",      # syntactically valid but too suspicious
    "bar.qwerty",   # long fake TLD
])
def test_no_fake_tlds(text):
    assert extract_bare_domains(text) == []


#
# 11. Mixed content: only real domains should match
#

@pytest.mark.parametrize("text, expected", [
    ("example.com /usr/bin/python test.org", ["example.com", "test.org"]),
    ("cmd.exe example.com foo.dll", ["example.com"]),
])
def test_mixed_content(text, expected):
    assert extract_bare_domains(text) == expected
