# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.optional_header import validate_optional_header
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]


# ---------------------------------------------------------
# 1) SizeOfImage < max section end
# ---------------------------------------------------------

def test_optional_header_inconsistent_size_of_image():
    metadata = {
        "optional_header": {"size_of_image": 200}
    }
    analysis = {
        "sections": [
            {"virtual_address": 100, "virtual_size": 200}, # ends at 300
        ]
    }
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INCONSISTENT_SIZE in make_issue_list(issues)


# ---------------------------------------------------------
# 2) SizeOfHeaders misaligned to FileAlignment
# ---------------------------------------------------------

def test_optional_header_invalid_size_of_headers_alignment():
    metadata = {
        "optional_header": {
            "size_of_headers": 300,
            "file_alignment": 256,
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 3) SizeOfHeaders < header_end
# ---------------------------------------------------------

def test_optional_header_invalid_size_of_headers_header_end():
    metadata = {
        "optional_header": {
            "size_of_headers": 200,
            "file_alignment": 200,
        },
        "header_end": 300,
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS in make_issue_list(issues)


# ---------------------------------------------------------
# 4) SectionAlignment < FileAlignment
# ---------------------------------------------------------

def test_optional_header_invalid_section_alignment_less_than_file_alignment():
    metadata = {
        "optional_header": {
            "section_alignment": 256,
            "file_alignment": 512,
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT in make_issue_list(issues)


# ---------------------------------------------------------
# 5) SectionAlignment not power of two
# ---------------------------------------------------------

def test_optional_header_invalid_section_alignment_not_power_of_two():
    metadata = {
        "optional_header": {
            "section_alignment": 300, # not power of two
            "file_alignment": 256,
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT in make_issue_list(issues)


# ---------------------------------------------------------
# 6) FileAlignment not power of two
# ---------------------------------------------------------

def test_optional_header_invalid_file_alignment_not_power_of_two():
    metadata = {
        "optional_header": {
            "file_alignment": 300, # not power of two
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT in make_issue_list(issues)


# ---------------------------------------------------------
# 7) FileAlignment out of recommended range
# ---------------------------------------------------------

def test_optional_header_invalid_file_alignment_out_of_range():
    metadata = {
        "optional_header": {
            "file_alignment": 128, # < 512
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT in make_issue_list(issues)


# ---------------------------------------------------------
# 8) SizeOfCode / Init / Uninit inconsistent
# ---------------------------------------------------------

def test_optional_header_size_fields_inconsistent():
    metadata = {
        "optional_header": {
            "size_of_code": 10,
            "size_of_initialized_data": 10,
            "size_of_uninitialized_data": 10,
        }
    }
    analysis = {
        "sections": [
            {"characteristics": 0x20, "raw_size": 50, "virtual_size": 0}, # code
            {"characteristics": 0x40, "raw_size": 50, "virtual_size": 0}, # init
            {"characteristics": 0x80, "raw_size": 0, "virtual_size": 50}, # uninit
        ]
    }
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_SIZE_FIELDS_INCONSISTENT in make_issue_list(issues)


# ---------------------------------------------------------
# 9) ImageBase misaligned
# ---------------------------------------------------------

def test_optional_header_image_base_misaligned():
    metadata = {
        "optional_header": {
            "image_base": 0x12345, # not 64K aligned
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED in make_issue_list(issues)


# ---------------------------------------------------------
# 10) NumberOfRvaAndSizes < 0 or > 16
# ---------------------------------------------------------

def test_optional_header_invalid_number_of_rva_and_sizes_range():
    metadata = {
        "optional_header": {
            "number_of_rva_and_sizes": 20, # > 16
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES in make_issue_list(issues)


# ---------------------------------------------------------
# 11) NumberOfRvaAndSizes < actual directories
# ---------------------------------------------------------

def test_optional_header_invalid_number_of_rva_and_sizes_too_small():
    metadata = {
        "optional_header": {
            "number_of_rva_and_sizes": 1,
            "data_directories": [1, 2], # 2 dirs > 1 allowed
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES in make_issue_list(issues)


# ---------------------------------------------------------
# 12) SizeOfImage misaligned to SectionAlignment
# ---------------------------------------------------------

def test_optional_header_size_of_image_misaligned():
    metadata = {
        "optional_header": {
            "size_of_image": 3000,
            "section_alignment": 4096,
        }
    }
    analysis = {"sections": []}
    issues = validate_optional_header(metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED in make_issue_list(issues)
