# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.version_info.validate_version_info.

Strategy:
- Input is the version_info_struct dict produced by parser_version_info.
  We construct dicts directly rather than running the parser, which
  isolates validator logic from parser behaviour.
- The analysis dict supplies sections and overlay_offset; minimal stubs
  cover everything the validator reads.
- Each test asserts on the set of REASONCODES emitted and the details
  payload, since both are part of the contract.

Layer note: this validator is @depends_on("internal", "analysis") and takes
TWO positional arguments. It reads only analysis["sections"] and does not use
SizeOfImage, so it was unaffected by the metadata-layer migration.

Details note: sub-reasons are carried in a "sub_reason" key. The key "reason"
is reserved by the heuristics emission layer, which merges details over its own
reason field - a details["reason"] would overwrite the parent reason code.

CAUTION when editing: several tests below narrow the details list with a
predicate such as `d.get("sub_reason") == "placement"` and then assert the
result is empty. If that key name ever drifts out of sync with the validator,
the predicate silently matches nothing and the test passes vacuously. Each such
test therefore ALSO asserts on the whole issue list, which cannot go vacuous.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.version_info import validate_version_info, _CHILD_ERROR_PRIORITY

_HEADER = ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER

# =================================================================
# Input builders
# =================================================================

def _make_analysis(
    rsrc_va: int = 0x1000,
    rsrc_vs: int = 0x2000,
    include_rsrc: bool = True,
    extra_sections: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build a minimal analysis dict with optional .rsrc section."""
    sections: List[Dict[str, Any]] = []
    if include_rsrc:
        sections.append({
            "name": ".rsrc",
            "virtual_address": rsrc_va,
            "virtual_size": rsrc_vs,
            "raw_address": 0x400,
            "raw_size": rsrc_vs,
        })
    if extra_sections:
        sections.extend(extra_sections)
    return {
        "sections": sections,
        "file_size": 0x10000,
        "overlay_offset": 0x9000,
    }


def _make_ffi(
    signature_ok: bool = True,
    struct_version_ok: bool = True,
    signature: int = 0xFEEF04BD,
    struct_version: int = 0x00010000,
) -> Dict[str, Any]:
    """Build a fixed_file_info sub-dict."""
    return {
        "signature": signature,
        "signature_ok": signature_ok,
        "struct_version": struct_version,
        "struct_version_ok": struct_version_ok,
        "file_version": (0x00010000, 0x00020003),
        "product_version": (0x00010000, 0x00020003),
        "file_flags_mask": 0,
        "file_flags": 0,
        "file_os": 0x00040004,
        "file_type": 1,
        "file_subtype": 0,
        "file_date": (0, 0),
    }


_NOT_PROVIDED = object()


def _make_vi(
    *,
    rva: Optional[int] = 0x1100,
    size: Optional[int] = 100,
    decoded: bool = True,
    header_ok: bool = True,
    length_consistent: bool = True,
    fixed_file_info: Any = _NOT_PROVIDED,
    string_file_info: Any = _NOT_PROVIDED,
    var_file_info: Any = _NOT_PROVIDED,
    errors: Any = _NOT_PROVIDED,
    w_type: int = 0,
) -> Dict[str, Any]:
    """Build a complete version_info_struct dict with sensible defaults."""
    return {
        "rva": rva,
        "size": size,
        "decoded": decoded,
        "header_ok": header_ok,
        "length_consistent": length_consistent,
        "w_type": w_type,
        "fixed_file_info": _make_ffi() if fixed_file_info is _NOT_PROVIDED else fixed_file_info,
        "string_file_info": [] if string_file_info is _NOT_PROVIDED else string_file_info,
        "var_file_info": [] if var_file_info is _NOT_PROVIDED else var_file_info,
        "errors": [] if errors is _NOT_PROVIDED else errors,
    }


def _codes(issues) -> List:
    """Extract REASONCODES from a list of StructuralIssue dicts."""
    return [issue["issue"] for issue in issues]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    """Return the details payloads for all issues matching a given code."""
    return [issue["details"] for issue in issues if issue["issue"] == code]


def _placement_details(issues) -> List[Dict[str, Any]]:
    """Header-issue details whose sub_reason is the placement check."""
    return [
        d for d in _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        if d.get("sub_reason") == "placement"
    ]


def _sub_reasons(issues):
    return [d.get("sub_reason") for d in _details_for(issues, _HEADER)]


def _run(vi, analysis=None):
    return validate_version_info({"version_info_struct": vi},
                                 analysis or _make_analysis())


# =================================================================
# Absence / clean cases
# =================================================================

class TestAbsence:
    """Absence of RT_VERSION is never a structural defect."""

    def test_no_version_info_struct_returns_no_issues(self):
        metadata = {}  # version_info_struct missing entirely
        issues = validate_version_info(metadata, _make_analysis())
        assert issues == []

    def test_explicit_none_returns_no_issues(self):
        metadata = {"version_info_struct": None}
        issues = validate_version_info(metadata, _make_analysis())
        assert issues == []


class TestCleanBlob:
    """A well-formed version_info_struct produces no issues."""

    def test_minimal_clean_blob(self):
        metadata = {"version_info_struct": _make_vi()}
        issues = validate_version_info(metadata, _make_analysis())
        assert issues == []

    def test_clean_blob_with_all_substructures(self):
        sfi = [{
            "tables": [{
                "lang_codepage": "040904B0",
                "strings": {"CompanyName": "MalX Labs"},
                "errors": [],
            }],
            "errors": [],
        }]
        vfi = [{
            "vars": [{
                "key": "Translation",
                "translations": [{"lang": 0x0409, "codepage": 0x04B0}],
            }],
            "errors": [],
        }]
        metadata = {"version_info_struct": _make_vi(
            string_file_info=sfi,
            var_file_info=vfi,
        )}
        issues = validate_version_info(metadata, _make_analysis())
        assert issues == []


# =================================================================
# Placement validation
# =================================================================

class TestPlacement:

    def test_placement_inside_rsrc_no_issue(self):
        vi = _make_vi(rva=0x1100, size=100)
        analysis = _make_analysis(rsrc_va=0x1000, rsrc_vs=0x2000)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER not in _codes(issues)

    def test_placement_rva_before_rsrc_flagged(self):
        vi = _make_vi(rva=0x500, size=100)
        analysis = _make_analysis(rsrc_va=0x1000, rsrc_vs=0x2000)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        assert len(_placement_details(issues)) == 1

    def test_placement_rva_extends_past_rsrc_flagged(self):
        vi = _make_vi(rva=0x2F00, size=0x200)
        analysis = _make_analysis(rsrc_va=0x1000, rsrc_vs=0x2000)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        placement_details = _placement_details(issues)
        assert len(placement_details) == 1
        assert placement_details[0]["rva"] == 0x2F00
        assert placement_details[0]["size"] == 0x200

    def test_placement_no_rsrc_section_skipped(self):
        """If there's no .rsrc section, placement isn't checked."""
        vi = _make_vi(rva=0x5000, size=100)
        analysis = _make_analysis(include_rsrc=False)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        assert _placement_details(issues) == []
        # Whole-list assertion: cannot pass vacuously if the predicate drifts.
        assert issues == []

    def test_placement_rva_none_skipped(self):
        """If the parser couldn't determine an RVA, placement isn't checked."""
        vi = _make_vi(rva=None, size=None)
        analysis = _make_analysis()
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        assert _placement_details(issues) == []
        assert issues == []

    def test_placement_size_none_treated_as_zero(self):
        """size=None is coerced to 0 by `vi['size'] or 0`."""
        vi = _make_vi(rva=0x1100, size=None)
        analysis = _make_analysis(rsrc_va=0x1000, rsrc_vs=0x2000)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        # 0x1100 + 0 is within .rsrc, so no placement issue
        assert _placement_details(issues) == []
        assert issues == []

    def test_placement_exact_boundary_no_issue(self):
        """RVA at rsrc_va and rva+size == rsrc_va + rsrc_vs is in-bounds."""
        vi = _make_vi(rva=0x1000, size=0x2000)
        analysis = _make_analysis(rsrc_va=0x1000, rsrc_vs=0x2000)
        issues = validate_version_info({"version_info_struct": vi}, analysis)
        assert _placement_details(issues) == []
        assert issues == []

    def test_placement_predicate_is_not_vacuous(self):
        """
        Guard for the helper itself: prove _placement_details CAN return a
        match. Without this, a drifted key name would make every
        "placement isn't checked" assertion above pass for the wrong reason.
        """
        vi = _make_vi(rva=0x5000, size=100)
        issues = validate_version_info({"version_info_struct": vi},
                                       _make_analysis())
        assert len(_placement_details(issues)) == 1


# =================================================================
# Top-level header validation
# =================================================================

class TestTopLevelHeader:

    def test_undecoded_emits_invalid_header_and_returns_early(self):
        """If decoded=False, no further sub-structure issues should be emitted."""
        vi = _make_vi(
            decoded=False,
            header_ok=False,
            length_consistent=False,
            fixed_file_info=None,
            errors=["too_short"],
        )
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())

        codes = _codes(issues)
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER in codes
        # Should not emit FFI/SFI/VFI codes because the validator returns early
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO not in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO not in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO not in codes

        # Details should carry the "undecoded" sub_reason and the parser errors
        header_details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        undecoded = [d for d in header_details if d.get("sub_reason") == "undecoded"]
        assert len(undecoded) == 1
        assert undecoded[0]["errors"] == ["too_short"]

    def test_szkey_mismatch_emits_invalid_header(self):
        vi = _make_vi(header_ok=False)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        szkey_details = [d for d in details if d.get("sub_reason") == "szkey_mismatch"]
        assert len(szkey_details) == 1

    def test_length_inconsistent_emits_invalid_header(self):
        vi = _make_vi(length_consistent=False)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        length_details = [d for d in details if d.get("sub_reason") == "length_inconsistent"]
        assert len(length_details) == 1

    def test_both_szkey_and_length_emit_two_separate_issues(self):
        vi = _make_vi(header_ok=False, length_consistent=False)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        reasons = [d.get("sub_reason") for d in details]
        assert "szkey_mismatch" in reasons
        assert "length_inconsistent" in reasons

    def test_undecoded_with_empty_errors_list(self):
        """decoded=False with no errors recorded — still emits header issue."""
        vi = _make_vi(decoded=False, errors=[])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER)
        undecoded = [d for d in details if d.get("sub_reason") == "undecoded"]
        assert len(undecoded) == 1
        assert undecoded[0]["errors"] == []


# =================================================================
# VS_FIXEDFILEINFO validation
# =================================================================

class TestFixedFileInfo:

    def test_clean_ffi_no_issue(self):
        vi = _make_vi(fixed_file_info=_make_ffi())
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO not in _codes(issues)

    def test_absent_ffi_without_errors_no_issue(self):
        """Legitimate omission: FFI is None and no parser errors flag it."""
        vi = _make_vi(fixed_file_info=None, errors=[])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO not in _codes(issues)

    def test_absent_ffi_with_parse_errors_flagged(self):
        vi = _make_vi(
            fixed_file_info=None,
            errors=["fixed_file_info_truncated"],
        )
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "parse_failed"
        assert "fixed_file_info_truncated" in details[0]["errors"]

    def test_absent_ffi_with_non_ffi_errors_not_flagged(self):
        """Parser errors unrelated to FFI shouldn't trigger an FFI issue."""
        vi = _make_vi(
            fixed_file_info=None,
            errors=["unknown_child", "child_length_invalid"],
        )
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO not in _codes(issues)

    def test_bad_signature_flagged(self):
        ffi = _make_ffi(signature_ok=False, signature=0xDEADBEEF)
        vi = _make_vi(fixed_file_info=ffi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO)
        sig_details = [d for d in details if d.get("sub_reason") == "signature"]
        assert len(sig_details) == 1
        assert sig_details[0]["signature"] == 0xDEADBEEF

    def test_bad_struct_version_flagged(self):
        ffi = _make_ffi(struct_version_ok=False, struct_version=0x00020000)
        vi = _make_vi(fixed_file_info=ffi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO)
        sv_details = [d for d in details if d.get("sub_reason") == "struct_version"]
        assert len(sv_details) == 1
        assert sv_details[0]["struct_version"] == 0x00020000

    def test_both_signature_and_struct_version_emit_two_issues(self):
        ffi = _make_ffi(signature_ok=False, struct_version_ok=False)
        vi = _make_vi(fixed_file_info=ffi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO)
        reasons = [d.get("sub_reason") for d in details]
        assert "signature" in reasons
        assert "struct_version" in reasons


# =================================================================
# StringFileInfo validation
# =================================================================

class TestStringFileInfo:

    def test_no_string_file_info_no_issue(self):
        vi = _make_vi(string_file_info=[])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO not in _codes(issues)

    def test_clean_string_file_info_no_issue(self):
        sfi = [{
            "tables": [{
                "lang_codepage": "040904B0",
                "strings": {"CompanyName": "X"},
                "errors": [],
            }],
            "errors": [],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO not in _codes(issues)

    def test_sfi_with_top_level_errors_flagged(self):
        """A StringFileInfo with errors on the wrapper itself."""
        sfi = [{
            "tables": [],
            "errors": ["string_table_header"],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO)
        assert len(details) == 1
        assert details[0]["errors"] == ["string_table_header"]
        assert details[0]["tables"] == 0

    def test_sfi_with_top_level_errors_skips_table_iteration(self):
        """Continue branch: top-level errors short-circuit table iteration."""
        sfi = [{
            "tables": [
                # This table has errors but should NOT produce a second issue
                # because the wrapper-level error already triggered `continue`.
                {"lang_codepage": "BAD", "strings": {}, "errors": ["lang_codepage_key"]},
            ],
            "errors": ["string_table_length"],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO)
        assert len(details) == 1  # only the wrapper-level error

    def test_sfi_table_with_errors_flagged(self):
        """A StringTable with its own errors but a clean wrapper."""
        sfi = [{
            "tables": [{
                "lang_codepage": "ENGLISHX",
                "strings": {"CompanyName": "X"},
                "errors": ["lang_codepage_key"],
            }],
            "errors": [],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO)
        assert len(details) == 1
        assert details[0]["errors"] == ["lang_codepage_key"]
        assert details[0]["lang_codepage"] == "ENGLISHX"

    def test_sfi_multiple_tables_each_with_errors_flagged_separately(self):
        sfi = [{
            "tables": [
                {"lang_codepage": "BAD1", "strings": {}, "errors": ["lang_codepage_key"]},
                {"lang_codepage": "BAD2", "strings": {}, "errors": ["string_length"]},
            ],
            "errors": [],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO)
        assert len(details) == 2
        codepages = [d["lang_codepage"] for d in details]
        assert "BAD1" in codepages
        assert "BAD2" in codepages

    def test_sfi_table_with_no_errors_not_flagged(self):
        """A clean table inside an SFI with no wrapper errors produces nothing."""
        sfi = [{
            "tables": [{
                "lang_codepage": "040904B0",
                "strings": {"X": "Y"},
                "errors": [],
            }],
            "errors": [],
        }]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO not in _codes(issues)

    def test_multiple_sfi_children(self):
        """Multiple StringFileInfo wrappers (unusual but legal)."""
        sfi = [
            {"tables": [], "errors": ["string_table_header"]},
            {"tables": [], "errors": ["string_table_length"]},
        ]
        vi = _make_vi(string_file_info=sfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO)
        assert len(details) == 2


# =================================================================
# VarFileInfo validation
# =================================================================

class TestVarFileInfo:

    def test_no_var_file_info_no_issue(self):
        vi = _make_vi(var_file_info=[])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO not in _codes(issues)

    def test_clean_var_file_info_no_issue(self):
        vfi = [{
            "vars": [{
                "key": "Translation",
                "translations": [{"lang": 0x0409, "codepage": 0x04B0}],
            }],
            "errors": [],
        }]
        vi = _make_vi(var_file_info=vfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO not in _codes(issues)

    def test_vfi_with_errors_flagged(self):
        vfi = [{
            "vars": [{"key": "Translation", "translations": []}],
            "errors": ["translation_not_dword_aligned"],
        }]
        vi = _make_vi(var_file_info=vfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO)
        assert len(details) == 1
        assert "translation_not_dword_aligned" in details[0]["errors"]
        assert details[0]["vars"] == 1

    def test_vfi_with_empty_vars_count(self):
        """vars list empty but errors present — details vars count should be 0."""
        vfi = [{"vars": [], "errors": ["var_header"]}]
        vi = _make_vi(var_file_info=vfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO)
        assert details[0]["vars"] == 0

    def test_multiple_vfi_children_each_with_errors(self):
        vfi = [
            {"vars": [], "errors": ["var_header"]},
            {"vars": [], "errors": ["var_length"]},
        ]
        vi = _make_vi(var_file_info=vfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        details = _details_for(issues, ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO)
        assert len(details) == 2

    def test_vfi_no_errors_not_flagged(self):
        """A VarFileInfo with vars but no errors produces nothing."""
        vfi = [{
            "vars": [{"key": "Translation", "translations": []}],
            "errors": [],
        }]
        vi = _make_vi(var_file_info=vfi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO not in _codes(issues)


# =================================================================
# Combination scenarios
# =================================================================

class TestCombinedAnomalies:
    """Multiple anomalies in a single blob — each fires independently."""

    def test_szkey_plus_bad_ffi_signature_emits_both(self):
        ffi = _make_ffi(signature_ok=False, signature=0xDEADBEEF)
        vi = _make_vi(header_ok=False, fixed_file_info=ffi)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        codes = _codes(issues)
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO in codes

    def test_placement_plus_sfi_plus_vfi_all_emit(self):
        sfi = [{"tables": [], "errors": ["string_table_header"]}]
        vfi = [{"vars": [], "errors": ["var_header"]}]
        vi = _make_vi(
            rva=0x5000,  # outside .rsrc
            size=100,
            string_file_info=sfi,
            var_file_info=vfi,
        )
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        codes = _codes(issues)
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO in codes


# =================================================================
# Child dispatch
# =================================================================

class TestChildDispatch:

    @pytest.mark.parametrize("tag", _CHILD_ERROR_PRIORITY)
    def test_every_child_tag_emits(self, tag):
        """
        Regression guard: each of these previously produced NO issue at all,
        because they are appended after decoded=True.
        """
        issues = _run(_make_vi(errors=[tag]))
        assert _sub_reasons(issues) == [tag]

    def test_details_carry_all_matching_tags(self):
        """
        unknown_child can repeat, and the count is the signal - a blob with
        five unrecognised children is more suspicious than one.
        """
        issues = _run(_make_vi(errors=["unknown_child"] * 3))
        details = _details_for(issues, _HEADER)
        assert len(details) == 1
        assert details[0]["errors"] == ["unknown_child"] * 3

    def test_one_issue_per_blob(self):
        issues = _run(_make_vi(errors=["unknown_child", "child_length_invalid"]))
        assert len(_details_for(issues, _HEADER)) == 1

    @pytest.mark.parametrize("errors,expected", [
        (["unknown_child", "child_length_invalid"], "child_length_invalid"),
        (["child_length_invalid", "unknown_child"], "child_length_invalid"),
        (["unknown_child", "child_header_unpack"], "child_header_unpack"),
        (["child_header_unpack", "child_length_invalid"], "child_header_unpack"),
    ])
    def test_walk_terminating_faults_win(self, errors, expected):
        """
        A fault that stopped the walk outranks one that did not: the
        remaining children were never examined.
        """
        assert _sub_reasons(_run(_make_vi(errors=errors))) == [expected]

    @pytest.mark.parametrize("higher,lower", list(
        zip(_CHILD_ERROR_PRIORITY, _CHILD_ERROR_PRIORITY[1:])))
    def test_priority_order_adjacent_pairs(self, higher, lower):
        for errors in ([higher, lower], [lower, higher]):
            assert _sub_reasons(_run(_make_vi(errors=errors))) == [higher]

    def test_priority_list_content(self):
        """
        Order is a contract; a behavioural test cannot catch a reorder,
        since _first_matching is definitionally consistent with whatever
        order the list has.
        """
        assert _CHILD_ERROR_PRIORITY == [
            "child_max_exceeded",
            "child_header_unpack",
            "child_length_invalid",
            "unknown_child",
        ]

    def test_clean_blob_emits_nothing(self):
        assert _run(_make_vi()) == []

    def test_unrelated_tags_ignored(self):
        issues = _run(_make_vi(errors=["some_future_tag"]))
        assert _codes(issues) == []

    def test_ffi_tag_does_not_trigger_the_child_branch(self):
        """
        The two branches read the same list with different filters and must
        not overlap: fixed_file_info_* belongs to the FFI branch alone.
        """
        issues = _run(_make_vi(errors=["fixed_file_info_truncated"],
                               fixed_file_info=None))
        assert _sub_reasons(issues) == []
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO in _codes(issues)

    def test_child_and_ffi_tags_both_reported(self):
        issues = _run(_make_vi(
            errors=["unknown_child", "fixed_file_info_truncated"],
            fixed_file_info=None))
        assert "unknown_child" in _sub_reasons(issues)
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO in _codes(issues)

    def test_child_details_exclude_non_child_tags(self):
        issues = _run(_make_vi(
            errors=["unknown_child", "fixed_file_info_truncated"],
            fixed_file_info=None))
        child = [d for d in _details_for(issues, _HEADER)
                 if d.get("sub_reason") == "unknown_child"][0]
        assert child["errors"] == ["unknown_child"]


class TestChildDispatchInteraction:

    def test_undecoded_short_circuits_the_child_branch(self):
        """
        When decoded is False the undecoded branch forwards the whole list
        and returns, so the child branch must not also fire.
        """
        issues = _run(_make_vi(decoded=False,
                               errors=["unknown_child", "too_short"]))
        assert _sub_reasons(issues) == ["undecoded"]
        assert _details_for(issues, _HEADER)[0]["errors"] == [
            "unknown_child", "too_short"]

    def test_child_branch_coexists_with_header_checks(self):
        issues = _run(_make_vi(header_ok=False, length_consistent=False,
                               errors=["unknown_child"]))
        assert _sub_reasons(issues) == [
            "szkey_mismatch", "length_inconsistent", "unknown_child"]

    def test_child_branch_follows_placement(self):
        """Emission order: placement, header checks, then child dispatch."""
        issues = _run(_make_vi(rva=0x5000, errors=["unknown_child"]))
        assert _sub_reasons(issues) == ["placement", "unknown_child"]

    def test_child_branch_does_not_suppress_sfi_or_vfi(self):
        issues = _run(_make_vi(
            errors=["unknown_child"],
            string_file_info=[{"tables": [], "errors": ["string_table_header"]}],
            var_file_info=[{"vars": [], "errors": ["var_header"]}]))
        codes = _codes(issues)
        assert _HEADER in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO in codes
        assert ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO in codes

    def test_missing_errors_key_tolerated(self):
        vi = _make_vi()
        del vi["errors"]
        assert _run(vi) == []

    def test_no_reserved_reason_key(self):
        issues = _run(_make_vi(errors=["unknown_child"]))
        assert issues
        assert all("reason" not in i["details"] for i in issues)

    def test_deterministic(self):
        import json
        vi = _make_vi(errors=["unknown_child", "child_length_invalid"],
                      header_ok=False)
        first = json.dumps(_run(vi), sort_keys=True)
        for _ in range(20):
            assert json.dumps(_run(vi), sort_keys=True) == first


# =================================================================
# Output shape contract
# =================================================================

class TestOutputContract:
    """Pin the shape of returned StructuralIssue objects."""

    def test_dependency_contract(self):
        assert getattr(validate_version_info, "_depends_on") == (
            "internal", "analysis")

    def test_returns_list(self):
        result = validate_version_info({"version_info_struct": _make_vi()}, _make_analysis())
        assert isinstance(result, list)

    def test_returns_empty_list_for_clean_blob(self):
        result = validate_version_info({"version_info_struct": _make_vi()}, _make_analysis())
        assert result == []

    def test_returns_empty_list_when_vi_absent(self):
        assert validate_version_info({}, _make_analysis()) == []
        assert validate_version_info({"version_info_struct": None}, _make_analysis()) == []

    def test_each_issue_has_issue_and_details(self):
        vi = _make_vi(header_ok=False)
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        for issue in issues:
            assert "issue" in issue
            assert "details" in issue
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"] would
        overwrite the parent reason code. Validators must use "sub_reason".

        Exercises placement, both header branches, both FFI branches, and the
        SFI/VFI paths together.
        """
        vi = _make_vi(
            rva=0x5000, size=100,          # placement
            header_ok=False,                # szkey_mismatch
            length_consistent=False,        # length_inconsistent
            fixed_file_info=_make_ffi(signature_ok=False, struct_version_ok=False),
            string_file_info=[{"tables": [], "errors": ["string_table_header"]}],
            var_file_info=[{"vars": [], "errors": ["var_header"]}],
        )
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_undecoded_path_avoids_reserved_reason_key(self):
        """The early-return path is unreachable above; pin it separately."""
        vi = _make_vi(decoded=False, fixed_file_info=None, errors=["too_short"])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert issues
        assert all("reason" not in i["details"] for i in issues)

    def test_ffi_parse_failed_path_avoids_reserved_reason_key(self):
        """The absent-FFI branch is mutually exclusive with the FFI checks."""
        vi = _make_vi(fixed_file_info=None, errors=["fixed_file_info_truncated"])
        issues = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert issues
        assert all("reason" not in i["details"] for i in issues)


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    """Same input → same output, always."""

    def test_repeated_validation_produces_identical_issues(self):
        ffi = _make_ffi(signature_ok=False)
        sfi = [{
            "tables": [{
                "lang_codepage": "BAD",
                "strings": {},
                "errors": ["lang_codepage_key"],
            }],
            "errors": [],
        }]
        vfi = [{"vars": [], "errors": ["translation_not_dword_aligned"]}]
        vi = _make_vi(
            header_ok=False,
            fixed_file_info=ffi,
            string_file_info=sfi,
            var_file_info=vfi,
        )
        metadata = {"version_info_struct": vi}
        analysis = _make_analysis()

        results = [validate_version_info(metadata, analysis) for _ in range(20)]
        codes_sequence = [_codes(r) for r in results]
        for seq in codes_sequence[1:]:
            assert seq == codes_sequence[0]

    def test_issue_ordering_is_stable(self):
        """The order in which issues are emitted should be deterministic."""
        vi = _make_vi(
            header_ok=False,
            length_consistent=False,
            fixed_file_info=_make_ffi(signature_ok=False, struct_version_ok=False),
        )
        result1 = validate_version_info({"version_info_struct": vi}, _make_analysis())
        result2 = validate_version_info({"version_info_struct": vi}, _make_analysis())
        assert _codes(result1) == _codes(result2)
