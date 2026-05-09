# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import random
import string
import idna
import pytest

from iocx.detectors.extractors.urls.bare_domain import _punycode_decodes_to_unicode

ASCII = string.ascii_lowercase + string.digits
UNICODE_SAMPLES = [
    "á", "é", "í", "ó", "ú", "ñ", "ü",
    "ß", "ø", "å", "ç",
    "д", "ж", "я", "ю", "ф",
    "λ", "π", "σ", "ω",
    "漢", "字", "語",
]

def random_ascii(n):
    return "".join(random.choice(ASCII) for _ in range(n))

def random_unicode(n):
    return "".join(random.choice(UNICODE_SAMPLES) for _ in range(n))


# ---------------------------------------------------------
# Generators
# ---------------------------------------------------------

def gen_valid_ascii_only_punycode():
    s = random_ascii(random.randint(5, 20))
    return idna.encode(s).decode(), s

def gen_valid_unicode_punycode():
    prefix = random_ascii(random.randint(5, 20))
    suffix = random_unicode(random.randint(1, 3))
    s = prefix + suffix
    return idna.encode(s).decode(), s

def gen_invalid_punycode():
    garbage = "".join(random.choice(string.punctuation) for _ in range(5))
    return "xn--" + garbage

def gen_long_ascii_only_punycode():
    prefix = random_ascii(random.randint(30, 50))
    return idna.encode(prefix).decode(), prefix

def gen_long_unicode_punycode():
    prefix = random_ascii(random.randint(30, 50))
    suffix = random_unicode(1)
    s = prefix + suffix
    return idna.encode(s).decode(), s


# ---------------------------------------------------------
# Fuzz Tests
# ---------------------------------------------------------
@pytest.mark.fuzz
def test_punycode_fuzzing():

    for _ in range(50):

        # 1. Valid ASCII-only punycode - should decode to ASCII - False
        puny, decoded = gen_valid_ascii_only_punycode()
        assert _punycode_decodes_to_unicode(puny) is False, f"ASCII-only punycode incorrectly returned True: {puny}"

        # 2. Valid Unicode punycode - should decode to Unicode - True
        puny, decoded = gen_valid_unicode_punycode()
        assert _punycode_decodes_to_unicode(puny) is True, f"Unicode punycode incorrectly returned False: {puny}"

        # 3. Invalid punycode - should return False
        invalid = gen_invalid_punycode()
        assert _punycode_decodes_to_unicode(invalid) is False, f"Invalid punycode incorrectly returned True: {invalid}"

        # 4. Long ASCII-only punycode - should decode to ASCII - False
        puny, decoded = gen_long_ascii_only_punycode()
        assert _punycode_decodes_to_unicode(puny) is False, f"Long ASCII punycode incorrectly returned True: {puny}"

        # 5. Long Unicode punycode - should decode to Unicode - True
        puny, decoded = gen_long_unicode_punycode()
        assert _punycode_decodes_to_unicode(puny) is True, f"Long Unicode punycode incorrectly returned False: {puny}"
