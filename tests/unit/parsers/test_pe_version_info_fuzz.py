# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0
"""
Parser/validator coverage driven by synthesised VS_VERSIONINFO blobs.

Each case is a single named deviation from a known-good baseline, so a
failure names the fault rather than "the blob is wrong somewhere". The
expectations below were verified against the real decoder.
"""

import pytest

from iocx.parsers.pe_version_info import _decode_vs_versioninfo
from examples.generators.python.generate_vs_versioninfo_fixtures import CASES, baseline


def _tables(out):
    return [t for s in out["string_file_info"] for t in s["tables"]]


def _all_errors(out):
    """Every tag at every level - what _error_total counts."""
    tags = list(out["errors"])
    for s in out["string_file_info"]:
        tags += s["errors"]
        for t in s["tables"]:
            tags += t["errors"]
    for v in out["var_file_info"]:
        tags += v["errors"]
    return tags


# =====================================================================
# Baseline
# =====================================================================

def test_baseline_is_clean():
    """If this fails, every expectation below is measuring the wrong thing."""
    out = _decode_vs_versioninfo(baseline())

    assert out["decoded"] is True
    assert out["header_ok"] is True
    assert out["length_consistent"] is True
    assert _all_errors(out) == []

    ffi = out["fixed_file_info"]
    assert ffi["signature_ok"] is True
    assert ffi["struct_version_ok"] is True

    tables = _tables(out)
    assert len(tables) == 1
    assert tables[0]["lang_codepage"] == "040904B0"
    assert tables[0]["strings"]["CompanyName"] == "MalX Labs"

    assert out["var_file_info"][0]["vars"][0]["translations"] == [
        {"lang": 0x0409, "codepage": 0x04B0}
    ]


def test_every_case_decodes_without_raising():
    """
    The parser's contract is to degrade, never to raise. A malformed blob
    that escapes as an exception aborts the whole analysis.
    """
    for name, fn in CASES.items():
        try:
            _decode_vs_versioninfo(fn())
        except Exception as exc:                      # noqa: BLE001
            pytest.fail(f"{name} raised {type(exc).__name__}: {exc}")


# =====================================================================
# Envelope faults
# =====================================================================

def test_szkey_mismatch():
    out = _decode_vs_versioninfo(CASES["szkey_mismatch"]())
    assert out["decoded"] is True
    assert out["header_ok"] is False
    # The fault is isolated: children still parse.
    assert len(_tables(out)) == 1


def test_length_inconsistent():
    out = _decode_vs_versioninfo(CASES["length_inconsistent"]())
    assert out["decoded"] is True
    assert out["length_consistent"] is False


def test_truncated_header():
    out = _decode_vs_versioninfo(CASES["truncated_header"]())
    assert out["decoded"] is False
    assert out["errors"] == ["too_short"]


# =====================================================================
# VS_FIXEDFILEINFO
# =====================================================================

@pytest.mark.parametrize("case, flag", [
    ("ffi_bad_signature", "signature_ok"),
    ("ffi_bad_struct_version", "struct_version_ok"),
])
def test_ffi_field_faults(case, flag):
    out = _decode_vs_versioninfo(CASES[case]())
    assert out["fixed_file_info"] is not None
    assert out["fixed_file_info"][flag] is False


def test_ffi_truncated():
    out = _decode_vs_versioninfo(CASES["ffi_truncated"]())
    assert out["fixed_file_info"] is None
    assert "fixed_file_info_truncated" in out["errors"]


def test_ffi_absent_is_not_a_defect():
    """wValueLength == 0 is a legitimate omission - no tag, no issue."""
    out = _decode_vs_versioninfo(CASES["ffi_absent"]())
    assert out["fixed_file_info"] is None
    assert not any(e.startswith("fixed_file_info") for e in out["errors"])


# =====================================================================
# Child dispatch
# =====================================================================

def test_unknown_child():
    out = _decode_vs_versioninfo(CASES["unknown_child"]())
    assert "unknown_child" in out["errors"]


def test_child_length_invalid_stops_the_walk():
    out = _decode_vs_versioninfo(CASES["child_length_invalid"]())
    assert "child_length_invalid" in out["errors"]
    assert _tables(out) == []


def test_child_max_exceeded_bounds_the_errors_list():
    """
    unknown_child does not break the walk, so without the 256 cap the
    errors list would scale with attacker-controlled input.
    """
    out = _decode_vs_versioninfo(CASES["child_max_exceeded"]())
    assert "child_max_exceeded" in out["errors"]
    assert out["errors"].count("unknown_child") <= 256


def test_child_priority_resolution():
    """
    Both tags are present; _CHILD_ERROR_PRIORITY must report the
    walk-terminating one, since the remaining children were never seen.
    """
    out = _decode_vs_versioninfo(CASES["child_max_exceeded"]())
    errs = out["errors"]
    assert "child_max_exceeded" in errs and "unknown_child" in errs


# =====================================================================
# StringFileInfo / VarFileInfo
# =====================================================================

def test_lang_codepage_key():
    out = _decode_vs_versioninfo(CASES["lang_codepage_key"]())
    assert _tables(out)[0]["errors"] == ["lang_codepage_key"]


def test_string_length_invalid():
    out = _decode_vs_versioninfo(CASES["string_length_invalid"]())
    assert "string_length" in _tables(out)[0]["errors"]


def test_translation_not_dword_aligned():
    out = _decode_vs_versioninfo(CASES["translation_not_dword_aligned"]())
    assert out["var_file_info"][0]["errors"] == ["translation_not_dword_aligned"]


# =====================================================================
# Projection-facing cases (parser accepts these; the projection acts)
# =====================================================================

def test_bidi_is_parsed_verbatim():
    """
    The parser must NOT sanitise - it records structural truth. Stripping
    belongs in the projection, and this case proves the raw text reaches
    it intact.
    """
    out = _decode_vs_versioninfo(CASES["bidi_in_company_name"]())
    company = _tables(out)[0]["strings"]["CompanyName"]
    assert "\u202e" in company
    assert "\n" in company
    assert _all_errors(out) == []      # not a structural defect


def test_many_tables_are_parsed_but_bounded_downstream():
    out = _decode_vs_versioninfo(CASES["deeply_nested_tables"]())
    assert len(_tables(out)) == 200
    assert _all_errors(out) == []
