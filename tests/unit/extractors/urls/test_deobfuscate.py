import pytest
from iocx.extractors.urls.deobfuscate import deobfuscate_text


def test_deobfuscate_hxxp():
    assert deobfuscate_text("hxxp://evil.com") == "http://evil.com"


def test_deobfuscate_bracket_dot():
    assert deobfuscate_text("test[.]com") == "test.com"


def test_deobfuscate_multiple_patterns():
    text = "hxxp[:]//example[.]com"
    assert deobfuscate_text(text) == "http://example.com"
