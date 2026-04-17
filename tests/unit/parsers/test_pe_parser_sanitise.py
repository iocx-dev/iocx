import pytest
from iocx.parsers.pe_parser import sanitize

def test_sanitize_none():
    assert sanitize(None) is None


def test_sanitize_bytes():
    assert sanitize(b"\x01\xab") == "01ab"


def test_sanitize_bytearray():
    assert sanitize(bytearray([0x10, 0x20])) == "1020"


def test_sanitize_tuple():
    result = sanitize((b"\xaa", 123, None))
    assert result == ("aa", 123, None)


def test_sanitize_list():
    result = sanitize([b"\x01", b"\x02"])
    assert result == ["01", "02"]


def test_sanitize_dict():
    result = sanitize({"a": b"\xff", "b": 5})
    assert result == {"a": "ff", "b": 5}


def test_sanitize_nested():
    obj = {
        "a": [b"\x01", (b"\x02", {"x": b"\x03"})],
        "b": None,
    }
    result = sanitize(obj)
    assert result == {
        "a": ["01", ("02", {"x": "03"})],
        "b": None,
    }


def test_sanitize_passthrough():
    # ints, strings, floats, bools should pass through unchanged
    assert sanitize(123) == 123
    assert sanitize("abc") == "abc"
    assert sanitize(1.5) == 1.5
    assert sanitize(True) is True

