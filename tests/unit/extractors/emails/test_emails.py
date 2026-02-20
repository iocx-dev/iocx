import pytest
from iocx.extractors.emails import extract

# ------------------------------------------------------------
# VALID EMAILS
# ------------------------------------------------------------

def test_basic_email():
    text = "Contact us at admin@example.com"
    assert extract(text) == ["admin@example.com"]


def test_email_with_subdomain():
    text = "support@mail.security.example.org"
    assert extract(text) == ["support@mail.security.example.org"]


def test_email_with_plus_tag():
    text = "user+tag@example.com"
    assert extract(text) == ["user+tag@example.com"]


def test_email_with_underscore_and_dash():
    text = "first_last-name@example.co.uk"
    assert extract(text) == ["first_last-name@example.co.uk"]


def test_uppercase_email():
    text = "Send to ADMIN@EXAMPLE.COM"
    assert extract(text) == ["ADMIN@EXAMPLE.COM"]


# ------------------------------------------------------------
# MULTIPLE EMAILS
# ------------------------------------------------------------

def test_multiple_emails():
    text = "a@example.com b@example.org c@example.net"
    assert extract(text) == [
        "a@example.com",
        "b@example.org",
        "c@example.net",
    ]


# ------------------------------------------------------------
# BOUNDARY BEHAVIOUR
# ------------------------------------------------------------

def test_email_followed_by_punctuation():
    text = "Email: admin@example.com,"
    assert extract(text) == ["admin@example.com"]


def test_email_preceded_by_parenthesis():
    text = "(admin@example.com)"
    assert extract(text) == ["admin@example.com"]


# ------------------------------------------------------------
# EMAILS INSIDE URLS
# ------------------------------------------------------------

def test_email_inside_url():
    # Your extractor *does* match this, because the regex allows it.
    text = "http://user@example.com/path"
    assert extract(text) == ["user@example.com"]


# ------------------------------------------------------------
# FALSE POSITIVE SUPPRESSION
# ------------------------------------------------------------

def test_does_not_match_invalid_domain():
    text = "user@invalid_domain"
    assert extract(text) == []


def test_does_not_match_missing_tld():
    text = "user@example"
    assert extract(text) == []


def test_does_not_match_missing_username():
    text = "@example.com"
    assert extract(text) == []


# ------------------------------------------------------------
# EDGE CASES
# ------------------------------------------------------------

def test_email_with_long_tld():
    text = "contact@domain.technology"
    assert extract(text) == ["contact@domain.technology"]


def test_email_with_multiple_dots_in_domain():
    text = "admin@a.b.c.example.com"
    assert extract(text) == ["admin@a.b.c.example.com"]


def test_email_with_percent_encoding():
    text = "user%test@example.com"
    assert extract(text) == ["user%test@example.com"]
