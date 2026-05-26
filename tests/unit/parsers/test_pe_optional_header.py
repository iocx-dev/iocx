# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.parsers.pe_optional_header import extract_optional_header_metadata


def test_extract_optional_header_metadata_no_optional_header():
    class FakePE:
        OPTIONAL_HEADER = None

    result = extract_optional_header_metadata(FakePE())

    assert result == {'optional_header_magic': None, 'number_of_rva_and_sizes': None}


def test_extract_optional_header_metadata_magic_not_int():
    class FakeOpt:
        Magic = "not-int"

    class FakePE:
        OPTIONAL_HEADER = FakeOpt()

    result = extract_optional_header_metadata(FakePE())

    assert result == {"optional_header_magic": None, 'number_of_rva_and_sizes': None}


def test_extract_optional_header_metadata_magic_int():
    class FakeOpt:
        Magic = 0x20B # PE32+

    class FakePE:
        OPTIONAL_HEADER = FakeOpt()

    result = extract_optional_header_metadata(FakePE())

    assert result == {"optional_header_magic": 0x20B, 'number_of_rva_and_sizes': None}
