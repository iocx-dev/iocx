# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.urls.bare_domain import _punycode_decodes_to_unicode, _detect_script


def test_punycode_non_punycode_returns_false():
    assert _punycode_decodes_to_unicode("example") is False
    assert _punycode_decodes_to_unicode("test-domain") is False
    assert _punycode_decodes_to_unicode("com") is False


def test_punycode_invalid_returns_false():
    assert _punycode_decodes_to_unicode("xn--") is False
    assert _punycode_decodes_to_unicode("xn--!") is False
    assert _punycode_decodes_to_unicode("xn--not-valid") is False


def test_punycode_valid_unicode_returns_true():
    assert _punycode_decodes_to_unicode("xn--fsq") is True # ß
    assert _punycode_decodes_to_unicode("xn--bcher-kva") is True # bücher
    assert _punycode_decodes_to_unicode("xn--d1acufc") is True # домен
    assert _punycode_decodes_to_unicode("xn--fiq228c") is True # 中文


def test_punycode_mixed_script_returns_true():
    assert _punycode_decodes_to_unicode("xn--e1awd7f") is True # аррӏе (looks like "apple")
    assert _punycode_decodes_to_unicode("xn--pple-43d") is True # ρρle


def test_punycode_idna_error_returns_false():
    assert _punycode_decodes_to_unicode("xn--a-ecp.ru") is False
    assert _punycode_decodes_to_unicode("xn--a-.com") is False


def test_punycode_combining_marks_returns_true():
    assert _punycode_decodes_to_unicode("xn--e-ufa") is True # e + combining acute


def test_punycode_long_unicode_returns_true():
    assert _punycode_decodes_to_unicode("xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-vid") is True


def test_punycode_leading_zero_edge_returns_true():
    assert _punycode_decodes_to_unicode("xn----7sbab5akq0a") is True


def test_detect_script_latin_only():
    # ASCII only → no scripts added → returns "Latin"
    assert _detect_script("hello") == "Latin"


def test_detect_script_greek_only():
    # Greek letter π → scripts = {"Greek"} → returns "Greek"
    assert _detect_script("π") == "Greek"


def test_detect_script_cyrillic_only():
    # Cyrillic letter я → scripts = {"Cyrillic"} → returns "Cyrillic"
    assert _detect_script("я") == "Cyrillic"


def test_detect_script_other_unicode():
    # Chinese character 漢 → scripts = {"Other"} → returns "Other"
    assert _detect_script("漢") == "Other"


def test_detect_script_mixed():
    # Greek π + Cyrillic я → scripts = {"Greek", "Cyrillic"} → returns "Mixed"
    assert _detect_script("πя") == "Mixed"
