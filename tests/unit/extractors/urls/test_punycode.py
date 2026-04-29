import pytest
from iocx.detectors.extractors.urls.bare_domain import _punycode_decodes_to_unicode


def test_punycode_non_punycode_returns_false():
    assert _punycode_decodes_to_unicode("example") is False
    assert _punycode_decodes_to_unicode("test-domain") is False
    assert _punycode_decodes_to_unicode("com") is False


def test_punycode_invalid_returns_true():
    assert _punycode_decodes_to_unicode("xn--") is True
    assert _punycode_decodes_to_unicode("xn--!") is True
    assert _punycode_decodes_to_unicode("xn--not-valid") is True


def test_punycode_valid_unicode_returns_true():
    assert _punycode_decodes_to_unicode("xn--fsq") is True # ß
    assert _punycode_decodes_to_unicode("xn--bcher-kva") is True # bücher
    assert _punycode_decodes_to_unicode("xn--d1acufc") is True # домен
    assert _punycode_decodes_to_unicode("xn--fiq228c") is True # 中文


def test_punycode_mixed_script_returns_true():
    assert _punycode_decodes_to_unicode("xn--e1awd7f") is True # аррӏе (looks like "apple")
    assert _punycode_decodes_to_unicode("xn--pple-43d") is True # ρρle


def test_punycode_idna_error_returns_true():
    assert _punycode_decodes_to_unicode("xn--a-ecp.ru") is True
    assert _punycode_decodes_to_unicode("xn--a-.com") is True


def test_punycode_combining_marks_returns_true():
    assert _punycode_decodes_to_unicode("xn--e-ufa") is True # e + combining acute


def test_punycode_long_unicode_returns_true():
    assert _punycode_decodes_to_unicode("xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-9gb") is True


def test_punycode_leading_zero_edge_returns_true():
    assert _punycode_decodes_to_unicode("xn----7sbab5akq0a") is True
