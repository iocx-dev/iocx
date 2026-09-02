# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.validators.resources.validate_resources.

Layer note: @depends_on("internal", "analysis"), TWO positional arguments.
The resource tree comes from internal["resources_struct"]; sections, file_size
and overlay_offset from analysis. Note the validator reads those three with
DIRECT SUBSCRIPTS (`analysis["sections"]`), so a missing key raises KeyError
rather than degrading - pinned below. Errors on a node drives
RESOURCE_DIRECTORY_ENTRY_UNREADABLE.

Fixture note: a data leaf is only well-formed at depth 2 (the Language layer).
Any leaf hung directly off the root is at depth 0 and therefore ALSO trips
RESOURCE_DATA_AT_INVALID_DEPTH. Tests targeting a data-entry check must either
build a full Type -> Name -> Language tree or assert the full issue list, or
they silently exercise two codes while claiming one.

The `_tree` helper below builds a correctly-shaped three-level tree so that
data-entry checks can be isolated.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.validators.resources import validate_resources, _DIRECTORY_ERROR_PRIORITY
from iocx.reason_codes import ReasonCodes


# .rsrc spans VA 0x1000..0x3000, raw 0x400..0x2400
RSRC_VA = 0x1000
RSRC_VS = 0x2000
RSRC_RAW = 0x400
RSRC_RAW_SIZE = 0x2000
FILE_SIZE = 0x10000
OVERLAY = 0xF000

UNREADABLE = ReasonCodes.RESOURCE_DIRECTORY_ENTRY_UNREADABLE
UNREADABLE_ST = ReasonCodes.RESOURCE_STRING_TABLE_UNREADABLE
CORRUPT_ST = ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT


# =================================================================
# Builders
# =================================================================

def _rsrc_section(va: Any = RSRC_VA, vs: Any = RSRC_VS,
                  raw: Any = RSRC_RAW, raw_size: Any = RSRC_RAW_SIZE) -> Dict[str, Any]:
    return {"name": ".rsrc", "virtual_address": va, "virtual_size": vs,
            "raw_address": raw, "raw_size": raw_size}


def _section(name: str, va: int, vs: int, raw: int, raw_size: int) -> Dict[str, Any]:
    return {"name": name, "virtual_address": va, "virtual_size": vs,
            "raw_address": raw, "raw_size": raw_size}


def _analysis(sections: Optional[List[Dict[str, Any]]] = None,
              file_size: Any = FILE_SIZE,
              overlay_offset: Any = OVERLAY) -> Dict[str, Any]:
    return {"sections": sections if sections is not None else [_rsrc_section()],
            "file_size": file_size, "overlay_offset": overlay_offset}


def _leaf(data_rva: Any = 0x1100, data_size: Any = 0x50,
          raw_offset: Any = 0x500, name: Any = None,
          entry_id: Any = 0x409) -> Dict[str, Any]:
    """A data-entry (leaf) child."""
    return {"name": name, "id": entry_id, "is_directory": False,
            "directory": None, "data_rva": data_rva, "data_size": data_size,
            "raw_offset": raw_offset}


def _node(rva: int, size: int = 24,
          entries: Optional[List[Dict[str, Any]]] = None,
          errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """A directory NODE (the thing `directory` points at)."""
    return {"rva": rva, "size": size, "entries": entries or [], "errors": errors or []}


def _subdir(target: Dict[str, Any], name: Any = None,
            entry_id: Any = 1) -> Dict[str, Any]:
    """A directory-entry child pointing at `target`."""
    return {"name": name, "id": entry_id, "is_directory": True,
            "directory": target, "data_rva": None, "data_size": None,
            "raw_offset": None}


def _tree(leaves: List[Dict[str, Any]],
          lang_rva: int = 0x1080, lang_errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    A correctly-shaped Type -> Name -> Language tree whose Language directory
    (depth 2) holds `leaves`. Lets data-entry checks be tested without also
    tripping RESOURCE_DATA_AT_INVALID_DEPTH.
    """
    lang = _node(lang_rva, 24, leaves, errors=lang_errors)
    name = _node(0x1040, 24, [_subdir(lang)])
    return _node(0x1000, 24, [_subdir(name)])


def _run(root: Dict[str, Any],
         analysis: Optional[Dict[str, Any]] = None,
         string_tables: Optional[List[Dict[str, Any]]] = None,
         resources: Any = "DEFAULT") -> List[Dict[str, Any]]:
    if resources == "DEFAULT":
        resources = {"root": root}
        if string_tables is not None:
            resources["string_tables"] = string_tables
    return validate_resources({"resources_struct": resources},
                              analysis or _analysis())


def _run_struct(root: Dict[str, Any],
    errors: Optional[List[str]] = None,
    string_tables: Optional[List[Dict[str, Any]]] = None,
    analysis: Optional[Dict[str, Any]] = None):
    """
    _run for tests needing a struct-level `errors` list - the sink
    `string_table_walk_failed` lands in, distinct from a directory node's
    own errors.
    """
    resources = {"root": root, "errors": errors or []}
    if string_tables is not None:
        resources["string_tables"] = string_tables
    return _run(root, analysis, resources=resources)


def make_issue_list(result) -> List[str]:
    return [i["issue"] for i in result]


def _details_for(issues, code) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues if i["issue"] == code]


def _directory(entries: Optional[List[Dict[str, Any]]] = None,
               rva: int = 0x1000, size: Optional[int] = None,
               errors: Optional[List[str]] = None) -> Dict[str, Any]:
    entries = entries or []
    return {"rva": rva, "size": size if size is not None else 16 + 8 * len(entries),
            "entries": entries, "errors": errors or []}


def _dir_entry(directory: Dict[str, Any], entry_id: Optional[int] = 1,
               name: Optional[str] = None) -> Dict[str, Any]:
    return {"name": name, "id": entry_id, "is_directory": True,
            "directory": directory, "data_rva": None, "data_size": None,
            "raw_offset": None}


def _data_entry(data_rva: int = 0x1100, data_size: int = 0x40,
                raw_offset: int = 0x500, entry_id: Optional[int] = 0x409,
                name: Optional[str] = None) -> Dict[str, Any]:
    return {"name": name, "id": entry_id, "is_directory": False,
            "directory": None, "data_rva": data_rva, "data_size": data_size,
            "raw_offset": raw_offset}


def _internal(root: Optional[Dict[str, Any]] = None,
              string_tables: Optional[List[Dict[str, Any]]] = None,
              errors: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"resources_struct": {
        "root": root if root is not None else _directory(),
        "string_tables": string_tables or [],
        "errors": errors or [],
    }}


def _codes(issues) -> List[str]:
    return [i["issue"] for i in issues]


# =================================================================
# Absence / early return
# =================================================================

class TestAbsence:

    def test_none_resources_struct(self):
        assert validate_resources({"resources_struct": None}, {}) == []

    def test_missing_resources_key(self):
        assert validate_resources({}, {}) == []

    @pytest.mark.parametrize("falsy", [{}, [], 0, False, ""])
    def test_any_falsy_resources_struct_returns_early(self, falsy):
        """
        The guard is `if not resources`, so an EMPTY dict short-circuits too -
        it never reaches the analysis subscripts.
        """
        assert validate_resources({"resources_struct": falsy}, {}) == []

    def test_no_rsrc_section_returns_early(self):
        analysis = _analysis(sections=[_section(".text", 0x1000, 0x1000,
                                                0x400, 0x1000)])
        assert _run(_node(0x1000, 24, [_leaf()]), analysis) == []

    def test_rsrc_match_is_case_insensitive(self):
        analysis = _analysis(sections=[
            {"name": ".RSRC", "virtual_address": RSRC_VA,
             "virtual_size": RSRC_VS, "raw_address": RSRC_RAW,
             "raw_size": RSRC_RAW_SIZE}])
        issues = _run(_node(0x1000, 0, []), analysis)
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH]

    def test_first_rsrc_section_wins(self):
        """`next(...)` takes the first match if a file declares two."""
        analysis = _analysis(sections=[
            _rsrc_section(va=0x1000, vs=0x2000),
            _rsrc_section(va=0x9000, vs=0x1000)])
        # root at 0x1000 is inside the FIRST .rsrc only
        assert _run(_node(0x1000, 0, []), analysis) != []


class TestAnalysisContract:
    """
    The validator uses direct subscripts for sections / file_size /
    overlay_offset. These pin the current (strict) contract so a change to
    `.get()` is a conscious one.
    """

    @pytest.mark.parametrize("missing", ["sections", "file_size",
                                         "overlay_offset"])
    def test_missing_analysis_key_raises(self, missing):
        analysis = _analysis()
        del analysis[missing]
        with pytest.raises(KeyError):
            _run(_node(0x1000, 24, [_leaf()]), analysis)

    def test_missing_analysis_key_tolerated_when_no_resources(self):
        """The early return happens before any analysis access."""
        assert validate_resources({"resources_struct": None}, {}) == []


# =================================================================
# Directory-level checks
# =================================================================

class TestDirectoryChecks:

    def test_directory_outside_rsrc_flagged(self):
        """
        A root directory outside .rsrc is reported rather than silently
        skipped. depth 0 identifies it as the root case.
        """
        issues = _run(_node(0x9999, 24, [_leaf()]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS]
        d = _details_for(issues,
                         ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS)[0]
        assert d["rva"] == 0x9999
        assert d["depth"] == 0
        assert d["rsrc_start"] == RSRC_VA
        assert d["rsrc_end"] == RSRC_VA + RSRC_VS

    def test_directory_partially_outside_rsrc_flagged(self):
        """The check is rva_in_rsrc(rva, size) - the whole node must fit."""
        issues = _run(_node(RSRC_VA + RSRC_VS - 8, 24, [_leaf()]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS]

    def test_directory_exactly_filling_rsrc_is_validated(self):
        """Boundary: rva + size == rsrc_end is inclusive."""
        issues = _run(_node(RSRC_VA + RSRC_VS - 24, 24, [_leaf(0x9999, 8)]))
        assert issues != []

    def test_zero_length_directory_flagged(self):
        issues = _run(_node(0x1000, 0, []))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH)[0] == {"rva": 0x1000}

    def test_zero_length_directory_stops_descent(self):
        """Entries are not walked once the zero-length check fires."""
        issues = _run(_node(0x1000, 0, [_leaf(0x9999, 0x50)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_ZERO_LENGTH]

    def test_self_referential_loop_flagged(self):
        loop = _node(0x1000, 24, [])
        loop["entries"] = [_subdir(loop)]
        issues = _run(loop)
        assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(issues)

    def test_mutual_loop_flagged(self):
        a = _node(0x1000, 24, [])
        b = _node(0x1100, 24, [])
        a["entries"] = [_subdir(b)]
        b["entries"] = [_subdir(a)]
        issues = _run(a)
        assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(issues)

    def test_shared_subtree_reported_as_loop(self):
        """
        `visited_dirs` is global rather than per-path, so a DAG - the same
        directory legitimately reached by two branches - is indistinguishable
        from a true cycle and is reported as a loop.

        Pinned as current behaviour: if shared subtrees are ever considered
        valid, this is the test that must change.
        """
        shared = _node(0x1200, 24, [_leaf()])
        root = _node(0x1000, 24, [
            _subdir(_node(0x1100, 24, [_subdir(shared)])),
            _subdir(_node(0x1180, 24, [_subdir(shared)])),
        ])
        assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(_run(root))

    def test_loop_detection_keys_on_rva_not_identity(self):
        """Two distinct nodes sharing an RVA collide in visited_dirs."""
        root = _node(0x1000, 24, [
            _subdir(_node(0x1100, 24, [])),
            _subdir(_node(0x1100, 24, [])),   # different object, same RVA
        ])
        assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(_run(root))

    def test_sibling_directories_at_distinct_rvas_are_fine(self):
        root = _node(0x1000, 24, [
            _subdir(_node(0x1100, 24, [])),
            _subdir(_node(0x1180, 24, [])),
        ])
        assert _run(root) == []


class TestDirectoryEntryUnreadable:
    """
    The parser skips an entry it cannot decode rather than aborting. Without
    these checks the skip is invisible: the directory reports fewer entries
    than its declared size implies and nothing says why.
    """

    def test_entry_decode_failed_emits(self):
        issues = _run(_node(0x1000, 24, [], errors=["entry_decode_failed"]))
        assert make_issue_list(issues) == [UNREADABLE]

    def test_directory_entries_unavailable_emits(self):
        issues = _run(_node(0x1000, 16, [],
                            errors=["directory_entries_unavailable"]))
        assert make_issue_list(issues) == [UNREADABLE]

    def test_details_expose_the_declared_decoded_gap(self):
        """
        `size` reflects the DECLARED entry count and `decoded_entries` the
        number actually built, so their difference is the loss. Neither alone
        conveys it.
        """
        issues = _run(_node(0x1000, 32, [], errors=["entry_decode_failed"]))
        assert _details_for(issues, UNREADABLE)[0] == {
            "rva": 0x1000, "depth": 0, "sub_reason": "entry_decode_failed",
            "failed_entry_count": 1, "declared_size": 32,
            "decoded_entries": 0}

    def test_failed_entry_count_counts_repeats(self):
        issues = _run(_node(0x1000, 40, [],
                            errors=["entry_decode_failed"] * 3))
        assert _details_for(issues, UNREADABLE)[0]["failed_entry_count"] == 3

    def test_one_issue_per_directory(self):
        """Priority-resolved: several tags still produce a single issue."""
        issues = _run(_node(0x1000, 16, [],
                            errors=["entry_decode_failed",
                                    "directory_entries_unavailable"]))
        assert len(_details_for(issues, UNREADABLE)) == 1

    def test_priority_unavailable_beats_decode_failed(self):
        """
        An unreadable entry LIST subsumes any per-entry failure - no entry
        was reached at all.
        """
        issues = _run(_node(0x1000, 16, [],
                            errors=["entry_decode_failed",
                                    "directory_entries_unavailable"]))
        assert _details_for(issues, UNREADABLE)[0]["sub_reason"] == (
            "directory_entries_unavailable")

    @pytest.mark.parametrize("higher,lower", list(
        zip(_DIRECTORY_ERROR_PRIORITY, _DIRECTORY_ERROR_PRIORITY[1:])))
    def test_priority_order_adjacent_pairs(self, higher, lower):
        """
        Adjacent pairs in both presentation orders. Pairing distant tags
        would only prove that some ordering exists.
        """
        for errors in ([higher, lower], [lower, higher]):
            issues = _run(_node(0x1000, 16, [], errors=errors))
            assert _details_for(issues, UNREADABLE)[0]["sub_reason"] == higher

    def test_priority_list_content(self):
        """
        Order is a contract, and a behavioural test cannot catch a reorder:
        _first_matching is definitionally consistent with whatever order the
        list happens to have, so fixtures derived from it move with it.
        """
        assert _DIRECTORY_ERROR_PRIORITY == [
            "directory_entries_unavailable",
            "entry_decode_failed",
        ]

    def test_unknown_tag_is_ignored(self):
        assert _run(_node(0x1000, 24, [], errors=["some_future_tag"])) == []

    def test_missing_errors_key_tolerated(self):
        """A struct predating the schema change must not raise."""
        node = _node(0x1000, 24, [])
        del node["errors"]
        assert _run(node) == []

    def test_nested_directory_errors_reported_at_depth(self):
        root = _tree([_leaf()], lang_errors=["entry_decode_failed"])
        details = _details_for(_run(root), UNREADABLE)[0]
        assert details["depth"] == 2
        assert details["rva"] == 0x1080

    def test_each_failing_directory_reports_separately(self):
        lang = _node(0x1080, 24, [_leaf()], errors=["entry_decode_failed"])
        name = _node(0x1040, 24, [_subdir(lang)],
                     errors=["entry_decode_failed"])
        root = _node(0x1000, 24, [_subdir(name)])
        assert [d["depth"] for d in _details_for(_run(root), UNREADABLE)] == [
            1, 2]


class TestDirectoryErrorSuppression:
    """
    The errors report sits after the placement and loop checks, so a
    directory the validator declines to process does not also report its
    contents.
    """

    def test_out_of_bounds_directory_does_not_report_errors(self):
        issues = _run(_node(0x9999, 16, [], errors=["entry_decode_failed"]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS]

    def test_looping_directory_does_not_report_errors_twice(self):
        """
        A directory reached twice reports the loop on the second visit, not
        a duplicate decode failure.
        """
        shared = _node(0x1080, 24, [], errors=["entry_decode_failed"])
        root = _node(0x1000, 24, [_subdir(shared), _subdir(shared)])
        issues = _run(root)
        assert len(_details_for(issues, UNREADABLE)) == 1
        assert ReasonCodes.RESOURCE_DIRECTORY_LOOP in make_issue_list(issues)

    def test_errors_do_not_suppress_the_entry_walk(self):
        """
        A directory with a decode failure still has its SURVIVING entries
        validated - the tag reports what was lost, not a reason to stop.
        """
        root = _tree([_leaf(0x9999, 0x50)],
                     lang_errors=["entry_decode_failed"])
        codes = make_issue_list(_run(root))
        assert UNREADABLE in codes
        assert ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS in codes

    def test_directory_errors_precede_entry_findings(self):
        """Emission order: the directory's own fault before its contents'."""
        root = _tree([_leaf(0x9999, 0x50)],
                     lang_errors=["entry_decode_failed"])
        codes = make_issue_list(_run(root))
        assert codes.index(UNREADABLE) < codes.index(
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)


# =================================================================
# Language layer (depth 2)
# =================================================================

class TestLanguageLayer:

    def _lang_tree(self, lang_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        lang = _node(0x1080, 24, lang_entries)
        name = _node(0x1040, 24, [_subdir(lang)])
        return _node(0x1000, 24, [_subdir(name)])

    def test_named_entry_at_language_layer_flagged(self):
        root = self._lang_tree([
            _subdir(_node(0x1090, 24, [_leaf()]), name="EN-US", entry_id=None)])
        issues = _run(root)
        assert ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID in make_issue_list(issues)
        d = _details_for(issues,
                         ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID)[0]
        assert d == {"rva": 0x1080, "name": "EN-US"}

    def test_integer_lcid_at_language_layer_is_fine(self):
        root = self._lang_tree([_leaf(entry_id=0x0409)])
        assert ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID not in \
            make_issue_list(_run(root))

    def test_each_named_entry_flagged_separately(self):
        root = self._lang_tree([
            _subdir(_node(0x1090, 24, []), name="EN-US", entry_id=None),
            _subdir(_node(0x10A0, 24, []), name="FR-FR", entry_id=None),
        ])
        names = [d["name"] for d in _details_for(
            _run(root), ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID)]
        assert names == ["EN-US", "FR-FR"]

    def test_entry_with_both_name_and_id_not_flagged(self):
        """The condition requires name set AND id None."""
        root = self._lang_tree([
            _subdir(_node(0x1090, 24, []), name="EN-US", entry_id=0x409)])
        assert ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID not in \
            make_issue_list(_run(root))

    def test_named_entries_at_type_and_name_layers_are_legal(self):
        """Only depth 2 requires integer IDs; named Types/Names are normal."""
        lang = _node(0x1080, 24, [_leaf()])
        name = _node(0x1040, 24, [_subdir(lang, name="MYNAME", entry_id=None)])
        root = _node(0x1000, 24, [_subdir(name, name="MYTYPE", entry_id=None)])
        assert ReasonCodes.RESOURCE_DIRECTORY_LANGUAGE_NOT_ID not in \
            make_issue_list(_run(root))


# =================================================================
# Data leaf depth
# =================================================================

class TestDataDepth:

    @pytest.mark.parametrize("depth", [0, 1])
    def test_leaf_above_language_layer_flagged(self, depth):
        leaf = _leaf(0x1100, 0x50, 0x500)
        node = _node(0x1080, 24, [leaf])
        for _ in range(depth):
            node = _node(0x1000 + 0x40 * depth, 24, [_subdir(node)])
        root = node if depth else _node(0x1000, 24, [leaf])
        issues = _run(root)
        assert ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH in make_issue_list(issues)

    def test_leaf_at_language_layer_not_flagged(self):
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]))
        assert ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH not in make_issue_list(issues)
        assert issues == []

    def test_leaf_below_language_layer_also_flagged(self):
        """
        The check is `depth != 2`, so a leaf that is too DEEP is flagged as
        well as one that is too shallow.
        """
        deep = _node(0x1300, 24, [_leaf(0x1400, 0x50, 0x500)])
        root = _node(0x1000, 24, [_subdir(
            _node(0x1100, 24, [_subdir(_node(0x1200, 24, [_subdir(deep)]))]))])
        issues = _run(root)
        assert ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH in make_issue_list(issues)
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH)[0]["depth"] == 3

    def test_invalid_depth_does_not_stop_data_validation(self):
        """
        The depth check falls through: a misplaced leaf is STILL bounds-checked,
        so both codes fire.
        """
        issues = _run(_node(0x1000, 24, [_leaf(0x9999, 0x50, 0x500)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH,
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]

    def test_details_payload(self):
        issues = _run(_node(0x1000, 24, [_leaf(0x1100, 0x50, 0x500)]))
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH)[0] == {
            "rva": 0x1000, "depth": 0, "data_rva": 0x1100}


# =================================================================
# Entry targets
# =================================================================

class TestEntryTargets:

    def test_subdirectory_outside_rsrc_flagged(self):
        root = _node(0x1000, 24, [_subdir(_node(0x9999, 24, []))])
        issues = _run(root)
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS)[0] == {
            "directory_rva": 0x1000, "target_rva": 0x9999}

    def test_out_of_bounds_target_does_not_stop_siblings(self):
        root = _node(0x1000, 24, [
            _subdir(_node(0x9999, 24, [])),
            _subdir(_node(0x8888, 24, [])),
        ])
        assert make_issue_list(_run(root)) == [
            ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS,
            ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS]

    def test_overflowing_target_caught_by_the_child_guard(self):
        """
        The entry check calls rva_in_rsrc(target_rva) with NO size, so a target
        starting inside .rsrc but overflowing it passes there. It is caught by
        the child's own guard instead - previously it vanished silently.

        depth 1 distinguishes this from the root case.
        """
        target = _node(RSRC_VA + RSRC_VS - 8, 24, [_leaf(0x9999, 0x50)])
        issues = _run(_node(0x1000, 24, [_subdir(target)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DIRECTORY_OUT_OF_BOUNDS)[0]["depth"] == 1

    def test_wholly_outside_target_still_reports_entry_code_only(self):
        """
        Control: a child wholly outside is caught by the CALLER, whose
        `continue` prevents descent - so the two codes never double-count.
        """
        issues = _run(_node(0x1000, 24, [_subdir(_node(0x9999, 24, []))]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_ENTRY_OUT_OF_BOUNDS]


# =================================================================
# Data-entry bounds
# =================================================================

class TestDataBounds:
    """All fixtures use a correctly-shaped tree so DATA_AT_INVALID_DEPTH
    does not confound the assertions."""

    def test_wellformed_leaf_is_silent(self):
        assert _run(_tree([_leaf(0x1100, 0x50, 0x500)])) == []

    def test_zero_size_data_flagged(self):
        issues = _run(_tree([_leaf(0x1100, 0, 0x500)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)[0] == {
            "data_rva": 0x1100, "data_size": 0}

    def test_data_rva_outside_rsrc_flagged(self):
        issues = _run(_tree([_leaf(0x9999, 0x50, 0x500)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]

    def test_data_overflowing_rsrc_end_flagged(self):
        issues = _run(_tree([_leaf(RSRC_VA + RSRC_VS - 8, 0x50, 0x500)]))
        assert ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS in make_issue_list(issues)

    def test_data_exactly_at_rsrc_end_is_fine(self):
        """Boundary: data_rva + data_size == rsrc_end is inclusive."""
        assert _run(_tree([_leaf(RSRC_VA + RSRC_VS - 0x50, 0x50, 0x500)])) == []

    def test_negative_raw_offset_flagged(self):
        """The -1 sentinel from a failed RVA->offset lookup lands here."""
        issues = _run(_tree([_leaf(0x1100, 0x50, -1)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)[0]["data_raw"] == -1

    def test_raw_past_file_size_flagged(self):
        issues = _run(_tree([_leaf(0x1100, 0x50, FILE_SIZE - 8)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]

    def test_raw_exactly_at_file_size_is_fine(self):
        """Boundary: data_raw + data_size == file_size is inclusive."""
        analysis = _analysis(overlay_offset=FILE_SIZE)
        assert _run(_tree([_leaf(0x1100, 0x50, FILE_SIZE - 0x50)]),
                    analysis) == []

    def test_bounds_checks_short_circuit_in_order(self):
        """
        Zero size wins over an out-of-range RVA: only ONE code per leaf.
        """
        issues = _run(_tree([_leaf(0x9999, 0, -1)]))
        assert len(issues) == 1
        assert _details_for(
            issues, ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)[0] == {
            "data_rva": 0x9999, "data_size": 0}

    def test_each_bad_leaf_reported(self):
        issues = _run(_tree([_leaf(0x1100, 0, 0x500),
                             _leaf(0x9999, 0x50, 0x500),
                             _leaf(0x1200, 0x50, 0x500)]))
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]


# =================================================================
# Overlap detection
# =================================================================

class TestOverlapDetection:

    def test_data_spanning_overlay_start_flagged(self):
        analysis = _analysis(overlay_offset=0x520)
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis)
        assert ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA in make_issue_list(issues)
        assert _details_for(
            issues,
            ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA)[0]["overlay_offset"] == 0x520

    def test_overlay_exactly_at_data_start_flagged(self):
        """The check is `data_raw <= overlay < data_raw + size` - inclusive."""
        analysis = _analysis(overlay_offset=0x500)
        assert ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA in make_issue_list(
            _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis))

    def test_overlay_exactly_at_data_end_not_flagged(self):
        """...and exclusive at the upper bound."""
        analysis = _analysis(overlay_offset=0x550)
        assert _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis) == []

    def test_raw_overlap_with_other_section_flagged(self):
        analysis = _analysis(sections=[
            _rsrc_section(), _section(".text", 0x8000, 0x100, 0x510, 0x20)])
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis)
        d = _details_for(issues, ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA)
        assert any(x.get("section") == ".text" and "data_raw" in x for x in d)

    def test_va_overlap_with_other_section_flagged(self):
        analysis = _analysis(sections=[
            _rsrc_section(), _section(".text", 0x1120, 0x100, 0x9000, 0x100)])
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis)
        d = _details_for(issues, ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA)
        assert any(x.get("section") == ".text" and "data_rva" in x for x in d)

    def test_rsrc_section_excluded_from_both_overlap_checks(self):
        """Resource data lives IN .rsrc; overlapping itself is not an anomaly."""
        assert _run(_tree([_leaf(0x1100, 0x50, 0x500)])) == []

    def test_raw_overlap_breaks_after_first_section(self):
        """One issue per leaf, not one per overlapping section."""
        analysis = _analysis(sections=[
            _rsrc_section(),
            _section(".a", 0x8000, 0x100, 0x510, 0x20),
            _section(".b", 0x8200, 0x100, 0x520, 0x20)])
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis)
        raw_hits = [d for d in _details_for(
            issues, ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA)
            if "data_raw" in d]
        assert len(raw_hits) == 1
        assert raw_hits[0]["section"] == ".a"

    def test_raw_and_va_overlaps_both_reported(self):
        """They are independent loops, so a leaf can trip both."""
        analysis = _analysis(sections=[
            _rsrc_section(), _section(".text", 0x1120, 0x100, 0x510, 0x20)])
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis)
        assert make_issue_list(issues).count(
            ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA) == 2

    def test_overlay_and_section_overlap_both_reported(self):
        analysis = _analysis(
            sections=[_rsrc_section(),
                      _section(".text", 0x8000, 0x100, 0x510, 0x20)],
            overlay_offset=0x520)
        assert make_issue_list(_run(_tree([_leaf(0x1100, 0x50, 0x500)]),
                                    analysis)).count(
            ReasonCodes.RESOURCE_DATA_OVERLAPS_OTHER_DATA) == 2

    def test_adjacent_raw_ranges_do_not_overlap(self):
        """Half-open: touching ranges are not an overlap."""
        analysis = _analysis(sections=[
            _rsrc_section(), _section(".text", 0x8000, 0x100, 0x550, 0x20)])
        assert _run(_tree([_leaf(0x1100, 0x50, 0x500)]), analysis) == []

    def test_out_of_bounds_data_never_reaches_overlap_checks(self):
        """The bounds `continue` short-circuits before overlap detection."""
        analysis = _analysis(
            sections=[_rsrc_section(),
                      _section(".text", 0x1120, 0x100, 0x510, 0x20)],
            overlay_offset=0x500)
        issues = _run(_tree([_leaf(0x1100, 0, 0x500)]), analysis)
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS]


# =================================================================
# String tables
# =================================================================

class TestStringTables:

    def test_valid_string_table_is_silent(self):
        assert _run(_node(0x1000, 24, []),
                    string_tables=[{"rva": 0x1100, "size": 0x20}]) == []

    def test_out_of_bounds_string_table_flagged(self):
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": 0x9999, "size": 0x20}])
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT]
        assert _details_for(
            issues, ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT)[0] == {
            "rva": 0x9999, "size": 0x20}

    def test_string_table_overflowing_rsrc_end_flagged(self):
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": RSRC_VA + RSRC_VS - 8,
                                      "size": 0x20}])
        assert ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT in make_issue_list(issues)

    def test_only_the_first_corrupt_table_is_reported(self):
        """The loop `break`s, so a second corrupt table is not reported."""
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": 0x9999, "size": 0x20},
                                     {"rva": 0x8888, "size": 0x20}])
        assert len(issues) == 1
        assert _details_for(
            issues, ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT)[0]["rva"] == 0x9999

    def test_valid_table_before_corrupt_one_still_reports(self):
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": 0x1100, "size": 0x20},
                                     {"rva": 0x9999, "size": 0x20}])
        assert _details_for(
            issues, ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT)[0]["rva"] == 0x9999

    def test_missing_string_tables_key_tolerated(self):
        """`resources.get("string_tables", [])` - unlike the analysis keys."""
        assert _run(_node(0x1000, 24, [])) == []

    def test_empty_string_tables_list(self):
        assert _run(_node(0x1000, 24, []), string_tables=[]) == []

    def test_string_tables_checked_even_when_tree_is_clean(self):
        issues = _run(_tree([_leaf(0x1100, 0x50, 0x500)]),
                      string_tables=[{"rva": 0x9999, "size": 0x20}])
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT]


class TestStringTableUnreadable:

    def test_walk_failure_emits(self):
        """
        Regression guard: without the membership test the tag is dropped and
        a malformed RT_STRING subtree reports clean.
        """
        issues = _run_struct(_node(0x1000, 24, []),
                             errors=["string_table_walk_failed"])
        assert make_issue_list(issues) == [UNREADABLE_ST]

    def test_details_carry_the_collected_count(self):
        """
        A non-empty list is not proof the walk finished, so the count is
        reported alongside the failure.
        """
        issues = _run_struct(_node(0x1000, 24, []),
                             errors=["string_table_walk_failed"],
                             string_tables=[{"rva": 0x1100, "size": 0x40}])
        assert _details_for(issues, UNREADABLE_ST)[0] == {
            "sub_reason": "walk_failed", "collected_tables": 1}

    def test_clean_errors_emit_nothing(self):
        assert _run_struct(_node(0x1000, 24, [])) == []

    def test_empty_string_tables_without_the_tag_is_silent(self):
        """
        The distinction the tag exists for: a binary with no string
        resources must stay silent.
        """
        assert _run_struct(_node(0x1000, 24, []), string_tables=[]) == []

    def test_unrelated_tag_does_not_emit(self):
        assert _run_struct(_node(0x1000, 24, []),
                           errors=["some_other_tag"]) == []

    def test_missing_struct_errors_key_tolerated(self):
        """`resources.get("errors") or []` - unlike the analysis keys."""
        assert _run(_node(0x1000, 24, [])) == []


class TestStringTableIndependence:
    """
    UNREADABLE (could not enumerate) and CORRUPT (a table is misplaced) are
    different facts and must co-fire on a partial walk.
    """

    def test_both_fire_together(self):
        issues = _run_struct(_node(0x1000, 24, []),
                             errors=["string_table_walk_failed"],
                             string_tables=[{"rva": 0x9999, "size": 0x40}])
        assert set(make_issue_list(issues)) == {UNREADABLE_ST, CORRUPT_ST}

    def test_unreadable_does_not_return_early(self):
        """
        The tag check must not suppress the table bounds loop. Note the
        in-bounds fixture here would pass either way; test_both_fire_together
        above is what actually catches an early return.
        """
        issues = _run_struct(_node(0x1000, 24, []),
                             errors=["string_table_walk_failed"],
                             string_tables=[{"rva": 0x1100, "size": 0x40}])
        assert make_issue_list(issues) == [UNREADABLE_ST]

    def test_unreadable_emitted_before_corrupt(self):
        issues = _run_struct(_node(0x1000, 24, []),
                             errors=["string_table_walk_failed"],
                             string_tables=[{"rva": 0x9999, "size": 0x40}])
        assert make_issue_list(issues)[0] == UNREADABLE_ST

    def test_corrupt_alone_without_walk_failure(self):
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": 0x9999, "size": 0x40}])
        assert make_issue_list(issues) == [CORRUPT_ST]

    def test_corrupt_breaks_after_the_first(self):
        """One issue per file, not per table."""
        issues = _run(_node(0x1000, 24, []),
                      string_tables=[{"rva": 0x9999, "size": 0x40},
                                     {"rva": 0x8888, "size": 0x40}])
        assert len(_details_for(issues, CORRUPT_ST)) == 1


# =================================================================
# Output contract
# =================================================================

class TestOutputContract:

    def test_dependency_contract(self):
        assert getattr(validate_resources, "_depends_on") == ("internal",
                                                              "analysis")

    def test_returns_list(self):
        assert isinstance(_run(_tree([_leaf()])), list)

    def test_each_issue_has_issue_and_details(self):
        issues = _run(_node(0x1000, 24, [_leaf(0x9999, 0x50)]))
        assert issues
        for issue in issues:
            assert set(issue) == {"issue", "details"}
            assert isinstance(issue["issue"], str)
            assert isinstance(issue["details"], dict)

    def test_no_details_payload_uses_reserved_reason_key(self):
        """
        "reason" is reserved by the heuristics emission layer: _det builds
        metadata as {"reason": parent, **details}, so a details["reason"]
        would overwrite the parent reason code. This validator uses no
        sub-reasons; the guard pins that none is introduced.
        """
        analysis = _analysis(
            sections=[_rsrc_section(),
                      _section(".text", 0x1120, 0x100, 0x510, 0x20)],
            overlay_offset=0x520)
        root = _node(0x1000, 24, [
            _leaf(0x1100, 0x50, 0x500),
            _subdir(_node(0x9999, 24, [])),
        ])
        issues = _run(root, analysis,
                      string_tables=[{"rva": 0x9999, "size": 0x20}])
        assert issues, "fixture should produce issues"
        offenders = [i["issue"] for i in issues if "reason" in i["details"]]
        assert not offenders, (
            f"details payload used the reserved key 'reason' for: {offenders}"
        )

    def test_json_serialisable(self):
        import json
        json.dumps(_run(_node(0x1000, 24, [_leaf(0x9999, 0x50)]),
                        string_tables=[{"rva": 0x9999, "size": 0x20}]))

    def test_inputs_are_not_mutated(self):
        import copy
        resources = {"root": _tree([_leaf(0x1100, 0x50, 0x500)]),
                     "string_tables": [{"rva": 0x1100, "size": 0x20}]}
        analysis = _analysis()
        res_snapshot = copy.deepcopy(resources)
        an_snapshot = copy.deepcopy(analysis)
        validate_resources({"resources_struct": resources}, analysis)
        assert resources == res_snapshot
        assert analysis == an_snapshot


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:

    def test_repeated_validation_is_identical(self):
        import json
        analysis = _analysis(
            sections=[_rsrc_section(),
                      _section(".text", 0x1120, 0x100, 0x510, 0x20)],
            overlay_offset=0x520)
        root = _node(0x1000, 24, [
            _leaf(0x1100, 0x50, 0x500),
            _leaf(0x9999, 0x50, 0x500),
            _subdir(_node(0x8888, 24, [])),
        ])
        resources = {"root": root, "string_tables": [{"rva": 0x9999, "size": 8}]}
        first = json.dumps(
            validate_resources({"resources_struct": resources}, analysis),
            sort_keys=True)
        for _ in range(20):
            assert json.dumps(
                validate_resources({"resources_struct": resources}, analysis),
                sort_keys=True) == first

    def test_emission_order_is_tree_then_string_tables(self):
        issues = _run(_node(0x1000, 24, [_leaf(0x9999, 0x50)]),
                      string_tables=[{"rva": 0x8888, "size": 0x20}])
        assert make_issue_list(issues) == [
            ReasonCodes.RESOURCE_DATA_AT_INVALID_DEPTH,
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS,
            ReasonCodes.RESOURCE_STRING_TABLE_CORRUPT,
        ]

    def test_entries_processed_in_order(self):
        issues = _run(_tree([_leaf(0x9991, 0x50), _leaf(0x9992, 0x50)]))
        rvas = [d["data_rva"] for d in _details_for(
            issues, ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)]
        assert rvas == [0x9991, 0x9992]

    def test_directory_errors_precede_entry_findings(self):
        lang = _node(0x1080, 24, [_leaf(0x9999, 0x50)])
        lang["errors"] = ["entry_decode_failed"]
        name = _node(0x1040, 24, [_subdir(lang)])
        root = _node(0x1000, 24, [_subdir(name)])
        codes = make_issue_list(_run(root))
        assert codes.index(
            ReasonCodes.RESOURCE_DIRECTORY_ENTRY_UNREADABLE) < codes.index(
            ReasonCodes.RESOURCE_DATA_OUT_OF_BOUNDS)
