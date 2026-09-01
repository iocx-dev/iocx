# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.imports.validate_imports.

Layer note: @depends_on("internal") - ONE positional argument. Placement is
deliberately not checked here (the RVA-graph backbone owns it), so no
metadata layer is needed.

Fixture note: the three pathology classes - DLL name, thunk source, and
per-entry - are fully independent. A descriptor carrying faults in two
classes emits one issue from each, so fixtures targeting one class must
leave the others clean or the assertions stop being single-anomaly.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.imports import (
    validate_imports,
    _DLL_NAME_ERROR_PRIORITY,
    _ENTRY_ERROR_PRIORITY,
    _MAX_ENTRY_ISSUES_PER_DESCRIPTOR,
    _THUNK_SOURCE_ERROR_PRIORITY,
)


# =================================================================
# Builders
# =================================================================

def _entry(index: int = 0,
           errors: Optional[List[str]] = None,
           **kw) -> Dict[str, Any]:
    """One ImportEntry as the parser emits it."""
    e = {"index": index, "errors": errors or [], "is_ordinal": False,
         "ordinal": None, "name": "Fn", "name_rva": 0x5000,
         "name_valid": True, "hint": 1, "thunk_value": 0x5000}
    e.update(kw)
    return e


def _descriptor(index: int = 0,
                errors: Optional[List[str]] = None,
                dll_name: Optional[str] = "KERNEL32.dll",
                imports: Optional[List[Dict[str, Any]]] = None,
                **kw) -> Dict[str, Any]:
    """One descriptor as the parser emits it."""
    d = {"index": index, "errors": errors or [], "dll_name": dll_name,
         "dll_name_valid": True, "name_rva": 0x2000,
         "bound_state": "unbound", "original_first_thunk": 0x3000,
         "first_thunk": 0x4000, "thunk_source": "int",
         "imports": imports or [], "timestamp": 0, "forwarder_chain": 0}
    d.update(kw)
    return d


def _internal(descriptors: Optional[List[Dict[str, Any]]] = None,
              truncations: Optional[List[str]] = None,
              errors: Optional[List[str]] = None) -> Dict[str, Any]:
    descriptors = descriptors or []
    return {"import_struct": {
        "rva": 0x1000, "size": 60, "is_64bit": True,
        "descriptors": descriptors,
        "descriptor_count": len(descriptors),
        "truncations": truncations or [],
        "errors": errors or [],
    }}


def _codes(issues) -> List[str]:
    return [i["issue"] for i in issues]


def _of(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


def _subs(issues, code) -> List[str]:
    return [d.get("sub_reason") for d in _of(issues, code)]


# =================================================================
# Priority-list content
# =================================================================

class TestPriorityListOrder:
    """
    The ORDER of each priority list is a contract, not an implementation
    detail: it decides which sub_reason a multi-fault entry reports.

    These assert the literal sequence, because a behavioural test cannot
    catch a reorder - _first_matching is definitionally consistent with
    whatever order the list happens to have, so fixtures derived from the
    list move with it. The behavioural pair tests below still earn their
    place by proving the lists are actually consulted; only these pin the
    order itself.
    """

    def test_dll_name_priority_order(self):
        assert _DLL_NAME_ERROR_PRIORITY == [
            # RVA-level
            "dll_name_rva_zero",
            # _read_asciiz read faults
            "rva_zero",
            "read_failed",
            "empty_read",
            "unterminated",
            "non_ascii",
            # content checks (three-way split, mutually exclusive)
            "dll_name_empty",
            "dll_name_not_printable",
            "dll_name_too_long",
        ]

    def test_thunk_source_priority_order(self):
        assert _THUNK_SOURCE_ERROR_PRIORITY == [
            "names_unrecoverable_bound_no_int",
            "no_thunk_array",
        ]

    def test_entry_priority_order(self):
        assert _ENTRY_ERROR_PRIORITY == [
            # ordinal path
            "ordinal_zero",
            # IMAGE_IMPORT_BY_NAME read faults
            "name_rva_zero",
            "name_read_failed",
            "name_too_short",
            "hint_unpack_failed",
            "name_unterminated",
            "name_non_ascii",
            # name content checks (mutually exclusive)
            "name_empty",
            "name_not_printable",
        ]

    def test_no_duplicates_within_a_list(self):
        for name, lst in (("dll", _DLL_NAME_ERROR_PRIORITY),
                          ("source", _THUNK_SOURCE_ERROR_PRIORITY),
                          ("entry", _ENTRY_ERROR_PRIORITY)):
            assert len(lst) == len(set(lst)), f"{name} list has duplicates"

    def test_descriptor_lists_are_disjoint(self):
        """
        Both read descriptor["errors"]; an overlapping tag would emit two
        issues for one fault.
        """
        assert not (set(_DLL_NAME_ERROR_PRIORITY)
                    & set(_THUNK_SOURCE_ERROR_PRIORITY))


# =================================================================
# Absence / short-circuit
# =================================================================

class TestAbsence:

    def test_no_import_struct_returns_empty(self):
        assert validate_imports({}) == []

    def test_none_import_struct_returns_empty(self):
        assert validate_imports({"import_struct": None}) == []

    def test_empty_directory_emits_nothing(self):
        assert validate_imports(_internal([])) == []

    def test_clean_descriptor_emits_nothing(self):
        assert validate_imports(_internal([_descriptor()])) == []


class TestTopLevelShortCircuit:

    def test_top_level_error_emits_one_issue(self):
        issues = validate_imports(
            _internal(errors=["descriptor_unpack_failed"]))
        assert _codes(issues) == [ReasonCodes.IMPORT_DIRECTORY_INVALID_HEADER]
        assert _subs(issues, ReasonCodes.IMPORT_DIRECTORY_INVALID_HEADER) == [
            "top_level_decode"]

    def test_top_level_error_suppresses_everything_else(self):
        """
        Without a usable descriptor array there is nothing further to say, so
        truncations and per-descriptor faults are not reported.
        """
        issues = validate_imports(_internal(
            descriptors=[_descriptor(errors=["dll_name_empty"])],
            truncations=["int_truncated"],
            errors=["descriptor_unpack_failed"],
        ))
        assert len(issues) == 1
        assert issues[0]["issue"] == ReasonCodes.IMPORT_DIRECTORY_INVALID_HEADER

    def test_errors_list_forwarded_verbatim(self):
        issues = validate_imports(_internal(errors=["a", "b"]))
        assert _of(issues, ReasonCodes.IMPORT_DIRECTORY_INVALID_HEADER)[0][
            "errors"] == ["a", "b"]


# =================================================================
# Truncations
# =================================================================

class TestTruncations:

    def test_one_issue_per_tag(self):
        issues = validate_imports(
            _internal(truncations=["int_truncated", "int_read_failed"]))
        assert _codes(issues) == [ReasonCodes.IMPORT_TABLE_TRUNCATED] * 2

    def test_tag_carried_in_table_key(self):
        issues = validate_imports(_internal(truncations=["int_truncated"]))
        assert _of(issues, ReasonCodes.IMPORT_TABLE_TRUNCATED)[0] == {
            "table": "int_truncated"}

    @pytest.mark.parametrize("tag", [
        "import_descriptor_unterminated",
        "import_descriptor_read_failed",
        "import_descriptor_truncated",
        "import_descriptor_max_exceeded",
        "int_read_failed", "int_truncated",
        "int_unpack_failed", "int_max_exceeded",
        "iat_fallback_read_failed", "iat_fallback_truncated",
        "iat_fallback_unpack_failed", "iat_fallback_max_exceeded",
    ])
    def test_every_parser_truncation_tag_is_forwarded(self, tag):
        """
        Truncations are forwarded wholesale, so no tag can be dropped. This
        enumerates the parser's full vocabulary as a contract guard.
        """
        issues = validate_imports(_internal(truncations=[tag]))
        assert _of(issues, ReasonCodes.IMPORT_TABLE_TRUNCATED)[0]["table"] == tag

    def test_fallback_prefix_distinguishes_the_array_read(self):
        """
        `int_*` vs `iat_fallback_*` tells a consumer which array was short -
        the fallback path only exists on older-linker binaries.
        """
        int_issues = validate_imports(_internal(truncations=["int_truncated"]))
        fb_issues = validate_imports(
            _internal(truncations=["iat_fallback_truncated"]))
        assert _of(int_issues, ReasonCodes.IMPORT_TABLE_TRUNCATED)[0][
            "table"] == "int_truncated"
        assert _of(fb_issues, ReasonCodes.IMPORT_TABLE_TRUNCATED)[0][
            "table"] == "iat_fallback_truncated"


# =================================================================
# DLL name class
# =================================================================

class TestDllName:

    @pytest.mark.parametrize("tag", _DLL_NAME_ERROR_PRIORITY)
    def test_every_priority_tag_emits(self, tag):
        """Contract guard: no tag in the list may be silently dropped."""
        issues = validate_imports(_internal([_descriptor(errors=[tag])]))
        assert _subs(issues, ReasonCodes.IMPORT_DLL_NAME_INVALID) == [tag]

    def test_details_payload(self):
        issues = validate_imports(_internal([
            _descriptor(index=2, errors=["dll_name_empty"],
                        dll_name="", name_rva=0x2222)]))
        assert _of(issues, ReasonCodes.IMPORT_DLL_NAME_INVALID)[0] == {
            "index": 2, "dll_name_rva": 0x2222, "dll_name": "",
            "sub_reason": "dll_name_empty"}

    def test_one_issue_per_descriptor(self):
        """Priority-resolved: several tags still produce a single issue."""
        issues = validate_imports(_internal([
            _descriptor(errors=["dll_name_rva_zero", "read_failed",
                                "dll_name_empty"])]))
        assert len(_of(issues, ReasonCodes.IMPORT_DLL_NAME_INVALID)) == 1

    @pytest.mark.parametrize("higher,lower", list(
        zip(_DLL_NAME_ERROR_PRIORITY, _DLL_NAME_ERROR_PRIORITY[1:])))
    def test_priority_order_adjacent_pairs(self, higher, lower):
        """Every adjacent pair, both presentation orders - see the entry-class
        equivalent for why distant pairs are insufficient."""
        for errors in ([higher, lower], [lower, higher]):
            issues = validate_imports(_internal([_descriptor(errors=errors)]))
            assert _subs(issues,
                         ReasonCodes.IMPORT_DLL_NAME_INVALID) == [higher]

    def test_each_descriptor_reported_separately(self):
        issues = validate_imports(_internal([
            _descriptor(index=0, errors=["dll_name_empty"]),
            _descriptor(index=1, errors=["dll_name_too_long"]),
        ]))
        details = _of(issues, ReasonCodes.IMPORT_DLL_NAME_INVALID)
        assert [d["index"] for d in details] == [0, 1]
        assert [d["sub_reason"] for d in details] == [
            "dll_name_empty", "dll_name_too_long"]


# =================================================================
# Thunk-source class
# =================================================================

class TestThunkSource:
    """
    A descriptor with no readable name source identifies the module but not
    its symbols - a different fact from a malformed DLL name, hence its own
    reason code.
    """

    @pytest.mark.parametrize("tag", _THUNK_SOURCE_ERROR_PRIORITY)
    def test_every_priority_tag_emits(self, tag):
        issues = validate_imports(_internal([_descriptor(errors=[tag])]))
        assert _subs(issues, ReasonCodes.IMPORT_DESCRIPTOR_INVALID) == [tag]

    def test_bound_without_int_details(self):
        """
        The details carry enough to explain WHY names are unrecoverable:
        old-style bound means FirstThunk holds addresses, and there is no INT.
        """
        issues = validate_imports(_internal([_descriptor(
            index=1, errors=["names_unrecoverable_bound_no_int"],
            dll_name="BOUND.dll", bound_state="bound_old_style",
            original_first_thunk=0, first_thunk=0x4000, thunk_source=None)]))
        assert _of(issues, ReasonCodes.IMPORT_DESCRIPTOR_INVALID)[0] == {
            "index": 1, "dll_name": "BOUND.dll",
            "bound_state": "bound_old_style",
            "original_first_thunk": 0, "first_thunk": 0x4000,
            "sub_reason": "names_unrecoverable_bound_no_int"}

    def test_no_thunk_array_details(self):
        issues = validate_imports(_internal([_descriptor(
            errors=["no_thunk_array"], original_first_thunk=0,
            first_thunk=0, thunk_source=None)]))
        d = _of(issues, ReasonCodes.IMPORT_DESCRIPTOR_INVALID)[0]
        assert d["sub_reason"] == "no_thunk_array"
        assert d["original_first_thunk"] == 0
        assert d["first_thunk"] == 0

    def test_priority_order(self):
        issues = validate_imports(_internal([_descriptor(
            errors=["no_thunk_array", "names_unrecoverable_bound_no_int"])]))
        assert _subs(issues, ReasonCodes.IMPORT_DESCRIPTOR_INVALID) == [
            "names_unrecoverable_bound_no_int"]

    def test_healthy_fallback_is_not_flagged(self):
        """
        The critical negative: OriginalFirstThunk == 0 with a usable fallback
        is legal and must produce nothing. Flagging it would misreport a large
        fraction of legitimate binaries.
        """
        issues = validate_imports(_internal([_descriptor(
            errors=[], original_first_thunk=0, first_thunk=0x4000,
            thunk_source="iat_fallback",
            imports=[_entry()])]))
        assert issues == []


# =================================================================
# Entry class
# =================================================================

class TestEntries:

    @pytest.mark.parametrize("tag", _ENTRY_ERROR_PRIORITY)
    def test_every_priority_tag_emits(self, tag):
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(errors=[tag])])]))
        assert _subs(issues, ReasonCodes.IMPORT_ENTRY_INVALID) == [tag]

    def test_details_payload(self):
        issues = validate_imports(_internal([_descriptor(
            index=3, dll_name="USER32.dll",
            imports=[_entry(index=7, errors=["ordinal_zero"],
                            is_ordinal=True, ordinal=0, name=None,
                            name_rva=None)])]))
        assert _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)[0] == {
            "descriptor_index": 3, "dll_name": "USER32.dll",
            "entry_index": 7, "is_ordinal": True, "ordinal": 0,
            "name": None, "name_rva": None,
            "sub_reason": "ordinal_zero", "invalid_entry_count": 1}

    def test_clean_entries_emit_nothing(self):
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(0), _entry(1), _entry(2)])]))
        assert issues == []

    def test_only_invalid_entries_reported(self):
        issues = validate_imports(_internal([_descriptor(imports=[
            _entry(0), _entry(1, ["ordinal_zero"]),
            _entry(2), _entry(3, ["name_empty"])])]))
        details = _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)
        assert [d["entry_index"] for d in details] == [1, 3]

    def test_invalid_entry_count_counts_invalid_not_total(self):
        """
        The count is of INVALID entries, not of the whole import list - a
        consumer reading it as a table size would be misled.
        """
        issues = validate_imports(_internal([_descriptor(imports=[
            _entry(0), _entry(1, ["ordinal_zero"]),
            _entry(2), _entry(3, ["name_empty"])])]))
        assert all(d["invalid_entry_count"] == 2
                   for d in _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID))

    @pytest.mark.parametrize("higher,lower", list(
        zip(_ENTRY_ERROR_PRIORITY, _ENTRY_ERROR_PRIORITY[1:])))
    def test_priority_order_adjacent_pairs(self, higher, lower):
        """
        Every ADJACENT pair, in both presentation orders. Pairing distant
        tags would only prove that some ordering exists - swapping two
        neighbours would go unnoticed. Driving the list itself also means a
        newly inserted tag is covered automatically.
        """
        for errors in ([higher, lower], [lower, higher]):
            issues = validate_imports(_internal([
                _descriptor(imports=[_entry(errors=errors)])]))
            assert _subs(issues, ReasonCodes.IMPORT_ENTRY_INVALID) == [higher]

    def test_entries_from_multiple_descriptors_are_attributed(self):
        issues = validate_imports(_internal([
            _descriptor(index=0, dll_name="A.dll",
                        imports=[_entry(0, ["ordinal_zero"])]),
            _descriptor(index=1, dll_name="B.dll",
                        imports=[_entry(0, ["name_empty"])]),
        ]))
        details = _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)
        assert [(d["descriptor_index"], d["dll_name"]) for d in details] == [
            (0, "A.dll"), (1, "B.dll")]


class TestEntryEmissionCap:

    def test_below_cap_all_emitted(self):
        n = _MAX_ENTRY_ISSUES_PER_DESCRIPTOR - 1
        issues = validate_imports(_internal([_descriptor(
            imports=[_entry(i, ["ordinal_zero"]) for i in range(n)])]))
        assert len(_of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)) == n

    def test_at_cap_all_emitted(self):
        n = _MAX_ENTRY_ISSUES_PER_DESCRIPTOR
        issues = validate_imports(_internal([_descriptor(
            imports=[_entry(i, ["ordinal_zero"]) for i in range(n)])]))
        assert len(_of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)) == n

    def test_above_cap_clamped_but_count_is_true(self):
        n = _MAX_ENTRY_ISSUES_PER_DESCRIPTOR + 20
        issues = validate_imports(_internal([_descriptor(
            imports=[_entry(i, ["ordinal_zero"]) for i in range(n)])]))
        details = _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)
        assert len(details) == _MAX_ENTRY_ISSUES_PER_DESCRIPTOR
        assert all(d["invalid_entry_count"] == n for d in details)

    def test_cap_is_per_descriptor_not_global(self):
        """
        A file with many malformed modules should not have later descriptors
        silenced by earlier ones.
        """
        n = _MAX_ENTRY_ISSUES_PER_DESCRIPTOR + 10
        bad = [_entry(i, ["ordinal_zero"]) for i in range(n)]
        issues = validate_imports(_internal([
            _descriptor(index=0, imports=list(bad)),
            _descriptor(index=1, imports=list(bad)),
        ]))
        details = _of(issues, ReasonCodes.IMPORT_ENTRY_INVALID)
        per = {}
        for d in details:
            per[d["descriptor_index"]] = per.get(d["descriptor_index"], 0) + 1
        assert per == {0: _MAX_ENTRY_ISSUES_PER_DESCRIPTOR,
                       1: _MAX_ENTRY_ISSUES_PER_DESCRIPTOR}


# =================================================================
# Class independence
# =================================================================

class TestClassIndependence:
    """
    The three pathology classes are orthogonal. These pin that they neither
    suppress one another nor merge, which is what makes the single-anomaly
    fixtures elsewhere in this file meaningful.
    """

    def test_dll_name_and_thunk_source_both_fire(self):
        issues = validate_imports(_internal([
            _descriptor(errors=["dll_name_empty", "no_thunk_array"])]))
        assert set(_codes(issues)) == {
            ReasonCodes.IMPORT_DLL_NAME_INVALID,
            ReasonCodes.IMPORT_DESCRIPTOR_INVALID}

    def test_descriptor_fault_does_not_suppress_entries(self):
        issues = validate_imports(_internal([_descriptor(
            errors=["dll_name_empty"],
            imports=[_entry(errors=["ordinal_zero"])])]))
        assert set(_codes(issues)) == {
            ReasonCodes.IMPORT_DLL_NAME_INVALID,
            ReasonCodes.IMPORT_ENTRY_INVALID}

    def test_truncations_do_not_suppress_descriptors(self):
        issues = validate_imports(_internal(
            descriptors=[_descriptor(errors=["dll_name_empty"])],
            truncations=["int_truncated"]))
        assert set(_codes(issues)) == {
            ReasonCodes.IMPORT_TABLE_TRUNCATED,
            ReasonCodes.IMPORT_DLL_NAME_INVALID}

    def test_all_three_classes_together(self):
        issues = validate_imports(_internal(
            descriptors=[_descriptor(
                errors=["dll_name_empty", "no_thunk_array"],
                imports=[_entry(errors=["ordinal_zero"])])],
            truncations=["int_truncated"]))
        assert set(_codes(issues)) == {
            ReasonCodes.IMPORT_TABLE_TRUNCATED,
            ReasonCodes.IMPORT_DLL_NAME_INVALID,
            ReasonCodes.IMPORT_DESCRIPTOR_INVALID,
            ReasonCodes.IMPORT_ENTRY_INVALID}


# =================================================================
# Placement ownership
# =================================================================

class TestPlacementNotChecked:
    """
    Placement is owned by the RVA-graph backbone. This validator must not
    assert it, or the two would double-count on every malformed directory.
    """

    def test_no_metadata_dependency(self):
        assert validate_imports._depends_on == ("internal",)

    def test_absurd_placement_emits_nothing(self):
        internal = _internal([_descriptor()])
        internal["import_struct"]["rva"] = 0x99999999
        internal["import_struct"]["size"] = 0x99999999
        assert validate_imports(internal) == []


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_issue_shape(self):
        issues = validate_imports(_internal(
            descriptors=[_descriptor(errors=["dll_name_empty"],
                                     imports=[_entry(errors=["ordinal_zero"])])],
            truncations=["int_truncated"]))
        assert issues
        for issue in issues:
            assert set(issue) == {"issue", "details"}
            assert isinstance(issue["issue"], str)
            assert isinstance(issue["details"], dict)

    def test_no_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer; a details key
        of that name would overwrite the parent code.
        """
        issues = validate_imports(_internal(
            descriptors=[_descriptor(
                errors=["dll_name_empty", "no_thunk_array"],
                imports=[_entry(errors=["ordinal_zero"])])],
            truncations=["int_truncated"]))
        assert issues
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders

    def test_json_serialisable(self):
        import json
        json.dumps(validate_imports(_internal(
            descriptors=[_descriptor(errors=["dll_name_empty"],
                                     imports=[_entry(errors=["name_empty"])])],
            truncations=["int_truncated"])))

    def test_input_not_mutated(self):
        import copy
        internal = _internal(
            descriptors=[_descriptor(errors=["dll_name_empty"],
                                     imports=[_entry(errors=["ordinal_zero"])])],
            truncations=["int_truncated"])
        snapshot = copy.deepcopy(internal)
        validate_imports(internal)
        assert internal == snapshot


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_identical(self):
        import json
        internal = _internal(
            descriptors=[
                _descriptor(index=0, errors=["dll_name_empty"],
                            imports=[_entry(0, ["ordinal_zero"]),
                                     _entry(1, ["name_empty"])]),
                _descriptor(index=1, errors=["no_thunk_array"]),
            ],
            truncations=["int_truncated", "iat_fallback_read_failed"])
        first = json.dumps(validate_imports(internal), sort_keys=True)
        for _ in range(20):
            assert json.dumps(validate_imports(internal),
                              sort_keys=True) == first

    def test_emission_order_is_truncations_then_descriptors(self):
        issues = validate_imports(_internal(
            descriptors=[_descriptor(errors=["dll_name_empty"])],
            truncations=["int_truncated"]))
        assert _codes(issues) == [ReasonCodes.IMPORT_TABLE_TRUNCATED,
                                  ReasonCodes.IMPORT_DLL_NAME_INVALID]

    def test_per_descriptor_order_is_name_then_source_then_entries(self):
        issues = validate_imports(_internal([_descriptor(
            errors=["dll_name_empty", "no_thunk_array"],
            imports=[_entry(errors=["ordinal_zero"])])]))
        assert _codes(issues) == [
            ReasonCodes.IMPORT_DLL_NAME_INVALID,
            ReasonCodes.IMPORT_DESCRIPTOR_INVALID,
            ReasonCodes.IMPORT_ENTRY_INVALID]
