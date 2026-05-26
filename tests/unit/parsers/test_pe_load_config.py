# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.parsers.pe_load_config import analyse_load_config


def test_analyse_load_config_no_directory():
    class FakePE:
        __data__ = b"\x00" * 100

    result = analyse_load_config(FakePE(), data_directories=[])

    assert result == {"parsed_size": 0}


def test_analyse_load_config_invalid_rva_or_size():
    class FakePE:
        __data__ = b"\x00" * 100

    dirs = [{"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": "bad", "size": 100}]

    result = analyse_load_config(FakePE(), dirs)

    assert result == {"parsed_size": 0}


def test_analyse_load_config_zero_rva_or_size():
    class FakePE:
        __data__ = b"\x00" * 100

    dirs = [{"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": 0, "size": 100}]

    result = analyse_load_config(FakePE(), dirs)

    assert result == {"parsed_size": 0}


def test_analyse_load_config_rva_mapping_fails():
    class FakeOptionalHeader:
        Magic = 0x10b # PE32

        def get_file_offset(self):
            return 0;

    class FakePE:
        __data__ = b"\x00" * 100
        OPTIONAL_HEADER = FakeOptionalHeader()

        def get_offset_from_rva(self, rva):
            return None # force early return

        def get_data(self, offset, size):
            return None

        DIRECTORY_ENTRY_LOAD_CONFIG = None

    dirs = [{"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": 0x1000, "size": 0x40}]

    result = analyse_load_config(FakePE(), dirs)

    assert result == {
        "parsed_size": 0,
        "security_cookie_rva": None,
        "seh_table_rva": None,
        "seh_count": None,
        "guard_cf_check_function_pointer": None,
        "guard_cf_dispatch_function_pointer": None,
        "guard_cf_function_table": None,
        "guard_cf_function_count": None,
        "time_date_stamp": None,
        "guard_flags": None,
    }

def test_analyse_load_config_rva_mapping_raises_peformaterror():
    from pefile import PEFormatError

    class FakeOptionalHeader:
        Magic = 0x10b
        def get_file_offset(self):
            return 0

    class FakePE:
        __data__ = b"\x00" * 100
        OPTIONAL_HEADER = FakeOptionalHeader()
        DIRECTORY_ENTRY_LOAD_CONFIG = None

        def get_offset_from_rva(self, rva):
            raise PEFormatError("forced failure")

    dirs = [{"name": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "rva": 0x1000, "size": 0x40}]

    result = analyse_load_config(FakePE(), dirs)

    assert result["parsed_size"] == 0
