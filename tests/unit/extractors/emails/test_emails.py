# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.emails import extract

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # Basic email
    (
        "Contact us at admin@example.com",
        ["admin@example.com"]
    ),

    # Subdomain
    (
        "support@mail.security.example.org",
        ["support@mail.security.example.org"]
    ),

    # Plus tag
    (
        "user+tag@example.com",
        ["user+tag@example.com"]
    ),

    # Underscore + dash
    (
        "first_last-name@example.co.uk",
        ["first_last-name@example.co.uk"]
    ),

    # Uppercase
    (
        "Send to ADMIN@EXAMPLE.COM",
        ["ADMIN@EXAMPLE.COM"]
    ),

    # Multiple emails
    (
        "a@example.com b@example.org c@example.net",
        ["a@example.com", "b@example.org", "c@example.net"]
    ),

    # Email followed by punctuation
    (
        "Email: admin@example.com,",
        ["admin@example.com"]
    ),

    # Email inside parentheses
    (
        "(admin@example.com)",
        ["admin@example.com"]
    ),

    # Email inside URL (allowed)
    (
        "http://user@example.com/path",
        ["user@example.com"]
    ),

    # Long TLD
    (
        "contact@domain.technology",
        ["contact@domain.technology"]
    ),

    # Multiple dots in domain
    (
        "admin@a.b.c.example.com",
        ["admin@a.b.c.example.com"]
    ),

    # Percent encoding allowed
    (
        "user%test@example.com",
        ["user%test@example.com"]
    ),
])
def test_email_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


# ------------------------------------------------------------
# NEGATIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text", [

    # Invalid domain
    "user@invalid_domain",

    # Missing TLD
    "user@example",

    # Missing username
    "@example.com",
])
def test_email_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
