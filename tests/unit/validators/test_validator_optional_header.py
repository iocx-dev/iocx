# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.validators.optional_header import validate_optional_header
from iocx.reason_codes import ReasonCodes


def make_issue_list(result):
    return [i["issue"] for i in result]

def _has(issues, code, sub_reason=None):
    """True if an issue with `code` (and optionally `sub_reason`) was emitted."""
    return any(
        i["issue"] == code
        and (sub_reason is None or i["details"].get("sub_reason") == sub_reason)
        for i in issues
    )


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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_INCONSISTENT_SIZE in make_issue_list(issues)


# ---------------------------------------------------------
# 2) SizeOfHeaders misaligned to FileAlignment
# ---------------------------------------------------------

def test_optional_header_invalid_size_of_headers_alignment():
    metadata = {
        "optional_header": {
            # 768 is not a multiple of 512 -> alignment branch.
            # fa=512 is a valid alignment, so no FILE_ALIGNMENT noise
            # (the old fa=256 was below the 512 minimum and also fired).
            "size_of_headers": 768,
            "file_alignment": 512,
        }
    }
    analysis = {"sections": []}
    internal = {"data_directories_raw": []}
    issues = validate_optional_header(internal, metadata, analysis)
    assert issues == [issues[0]]   # single anomaly
    assert issues[0]["issue"] == ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS
    assert "file_alignment" in issues[0]["details"]        # alignment branch
    assert "required_minimum" not in issues[0]["details"]  # not the header_end branch


# ---------------------------------------------------------
# 3) SizeOfHeaders < header_end
# ---------------------------------------------------------

def test_optional_header_invalid_size_of_headers_header_end():
    metadata = {
        "optional_header": {
            # 1024 IS a multiple of 512, so the alignment branch stays quiet;
            # only the header_end branch fires.
            "size_of_headers": 1024,
            "file_alignment": 512,
        },
        "header_end": 2048,
    }
    analysis = {"sections": []}
    internal = {"data_directories_raw": []}
    issues = validate_optional_header(internal, metadata, analysis)
    assert len(issues) == 1
    assert issues[0]["issue"] == ReasonCodes.OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS
    assert issues[0]["details"]["required_minimum"] == 2048   # header_end branch


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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
    assert _has(issues, ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT)
    # the sa<fa branch carries no sub_reason; the not-pow2 branch does
    assert not _has(issues, ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                    "not_power_of_two")


# ---------------------------------------------------------
# 5) SectionAlignment not power of two
# ---------------------------------------------------------

def test_optional_header_invalid_section_alignment_not_power_of_two():
    metadata = {
        "optional_header": {
            # 768 is >= fa (so the sa<fa branch stays quiet) and is not a
            # power of two. The old sa=300/fa=256 fired out_of_range on fa too.
            "section_alignment": 768,
            "file_alignment": 512,
        }
    }
    analysis = {"sections": []}
    internal = {"data_directories_raw": []}
    issues = validate_optional_header(internal, metadata, analysis)
    assert len(issues) == 1
    assert _has(issues, ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                "not_power_of_two")


# ---------------------------------------------------------
# 6) FileAlignment not power of two
# ---------------------------------------------------------

def test_optional_header_invalid_file_alignment_not_power_of_two():
    metadata = {
        "optional_header": {
            # 768 is not a power of two but IS within 512..64K, isolating
            # not_power_of_two. The old value (300) was ALSO below 512, so the
            # fixture emitted out_of_range too - and because both share the
            # same parent code, the old assertion would have passed even if
            # the power-of-two branch were removed entirely.
            "file_alignment": 768,
        }
    }
    analysis = {"sections": []}
    internal = {"data_directories_raw": []}
    issues = validate_optional_header(internal, metadata, analysis)
    assert len(issues) == 1
    assert _has(issues, ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                "not_power_of_two")


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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
    # fa=128 is already a power of two, so this fixture is clean as written
    assert _has(issues, ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                "out_of_range")


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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED in make_issue_list(issues)


# ---------------------------------------------------------
# 10) NumberOfRvaAndSizes < 0 or > 16
# ---------------------------------------------------------

def test_optional_header_invalid_number_of_rva_and_sizes_range():
    metadata = {}
    analysis = {"sections": [], "data_directories": []}
    internal = {
        "number_of_rva_and_sizes": 20,
        "data_directories_raw": [], # can be empty for this case
    }

    issues = validate_optional_header(internal, metadata, analysis)
    assert len(issues) == 1
    assert "actual_directories" not in issues[0]["details"]


# ---------------------------------------------------------
# 11) NumberOfRvaAndSizes < actual directories
# ---------------------------------------------------------

def test_optional_header_invalid_number_of_rva_and_sizes_too_small():
    metadata = {}

    analysis = {"sections": [], "data_directories": [1, 2]} # not used here
    internal = {
        "number_of_rva_and_sizes": 1,
        "data_directories_raw": [
            {"rva": 0x1000, "size": 0x40},
            {"rva": 0x2000, "size": 0x40},
        ],
    }

    issues = validate_optional_header(internal, metadata, analysis)
    assert issues[0]["details"]["actual_directories"] == 2


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
    internal = {
        "data_directories_raw": []
    }
    issues = validate_optional_header(internal, metadata, analysis)
    assert ReasonCodes.OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED in make_issue_list(issues)


# --------------------------------------------------------------------
# 13) Disambiguation test, since `not_power_of_two` has two parents
# --------------------------------------------------------------------

def test_shared_not_power_of_two_is_disambiguated_by_parent():
    """
    "not_power_of_two" is emitted by BOTH OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT
    and OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT. The parent code is what separates
    them - precisely the ambiguity the reason collision created, where both
    surfaced as the bare string "not_power_of_two".
    """
    internal = {"data_directories_raw": []}
    analysis = {"sections": []}

    sec = validate_optional_header(
        internal, {"optional_header": {"section_alignment": 768,
                                       "file_alignment": 512}}, analysis)
    fil = validate_optional_header(
        internal, {"optional_header": {"file_alignment": 768}}, analysis)

    assert _has(sec, ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                "not_power_of_two")
    assert not _has(sec, ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                    "not_power_of_two")

    assert _has(fil, ReasonCodes.OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT,
                "not_power_of_two")
    assert not _has(fil, ReasonCodes.OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT,
                    "not_power_of_two")

# --------------------------------------------------------------------
# 14) Contract and reason key tests
# --------------------------------------------------------------------

def test_dependency_contract():
    assert getattr(validate_optional_header, "_depends_on") == (
        "internal", "metadata", "analysis")


def test_no_details_payload_uses_reserved_reason_key():
    """
    "reason" is reserved by the heuristics emission layer: _det builds metadata
    as {"reason": parent, **details}, so a details["reason"] would overwrite
    the parent reason code. Validators must use "sub_reason".
    """
    metadata = {"optional_header": {
        "size_of_image": 200, "section_alignment": 300, "file_alignment": 300,
        "size_of_headers": 300, "image_base": 0x12345,
    }}
    analysis = {"sections": [{"virtual_address": 100, "virtual_size": 200}]}
    internal = {"number_of_rva_and_sizes": 20, "data_directories_raw": []}
    issues = validate_optional_header(internal, metadata, analysis)
    assert issues, "fixture should produce issues"
    offenders = [i["issue"] for i in issues if "reason" in i["details"]]
    assert not offenders, (
        f"details payload used the reserved key 'reason' for: {offenders}"
    )
