# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Coverage for the `reason == "unknown"` branch in _validate_entries.

This branch IS the silent-drop mechanism this workstream has spent its time
closing: an entry carrying only tags absent from _ENTRY_ERROR_PRIORITY is
skipped entirely - no issue, and no contribution to invalid_entry_count.

It is UNREACHABLE with current parser output. Every tag pe_imports can place
in entry["errors"] appears in the priority list, verified statically by the
tag-contract check. The branch exists to absorb a future parser tag that
someone forgets to register, which is precisely how `empty_read`,
`dll_name_empty`, `dll_name_too_long` and `ordinal_index_duplicate` were all
lost in other subsystems.

These tests therefore pin behaviour that is defensible but not obviously
desirable. They exist so that:
  * the branch is covered rather than dead;
  * the consequence (total invisibility, including in the count) is written
    down rather than discovered;
  * a change to that behaviour is a deliberate decision, not a drift.

The real guard against the drop is the tag-contract test, which fails CI
when a parser gains a tag no validator consumes. This suite is the
belt-and-braces record of what happens if that guard is ever bypassed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.validators.imports import (
    validate_imports,
    _ENTRY_ERROR_PRIORITY,
    _MAX_ENTRY_ISSUES_PER_DESCRIPTOR,
)


# Every tag pe_imports can place in entry["errors"]. Kept as a literal so a
# parser change that adds a tag makes test_branch_is_unreachable_today fail,
# rather than the list silently tracking the parser.
_PARSER_ENTRY_TAGS = frozenset({
    "ordinal_zero", "name_rva_zero", "name_read_failed", "name_too_short",
    "hint_unpack_failed", "name_unterminated", "name_non_ascii",
    "name_empty", "name_not_printable",
})

_UNKNOWN = "some_future_parser_tag"


# =================================================================
# Builders
# =================================================================

def _entry(index: int = 0, errors: Optional[List[str]] = None,
           **kw) -> Dict[str, Any]:
    e = {"index": index, "errors": errors or [], "is_ordinal": False,
         "ordinal": None, "name": "Fn", "name_rva": 0x5000,
         "name_valid": True, "hint": 1, "thunk_value": 0x5000}
    e.update(kw)
    return e


def _descriptor(index: int = 0, imports: Optional[List[Dict]] = None,
                errors: Optional[List[str]] = None,
                dll_name: str = "KERNEL32.dll") -> Dict[str, Any]:
    return {"index": index, "errors": errors or [], "dll_name": dll_name,
            "dll_name_valid": True, "name_rva": 0x2000,
            "bound_state": "unbound", "original_first_thunk": 0x3000,
            "first_thunk": 0x4000, "thunk_source": "int",
            "imports": imports or []}


def _internal(descriptors: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"import_struct": {
        "rva": 0x1000, "size": 60, "is_64bit": True,
        "descriptors": descriptors, "descriptor_count": len(descriptors),
        "truncations": [], "errors": []}}


def _entry_issues(issues) -> List[Dict[str, Any]]:
    return [i["details"] for i in issues
            if i["issue"] == ReasonCodes.IMPORT_ENTRY_INVALID]


# =================================================================
# Reachability
# =================================================================

class TestBranchReachability:

    def test_branch_is_unreachable_with_current_parser_tags(self):
        """
        Guard on the guard: every tag pe_imports can emit must appear in the
        priority list, so the unknown branch cannot fire in production. If
        this fails, a parser tag has been added without registering it - and
        the entries carrying it are being silently dropped right now.
        """
        unregistered = _PARSER_ENTRY_TAGS - set(_ENTRY_ERROR_PRIORITY)
        assert not unregistered, (
            f"parser tags missing from _ENTRY_ERROR_PRIORITY: "
            f"{sorted(unregistered)} - entries carrying these are dropped")

    def test_priority_list_has_no_phantom_entries(self):
        """The inverse: a listed tag no parser produces implies a routing
        that does not exist."""
        phantom = set(_ENTRY_ERROR_PRIORITY) - _PARSER_ENTRY_TAGS
        assert not phantom, f"unreachable tags in priority list: {sorted(phantom)}"


# =================================================================
# The branch itself
# =================================================================

class TestUnknownEntryTagIsDropped:

    def test_entry_with_only_unknown_tags_emits_nothing(self):
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(0, [_UNKNOWN])])]))
        assert _entry_issues(issues) == []

    def test_multiple_unknown_tags_on_one_entry(self):
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(0, [_UNKNOWN, "another_unknown"])])]))
        assert _entry_issues(issues) == []

    def test_all_entries_unknown_takes_the_empty_return(self):
        """
        With nothing collected, `if not invalid: return` fires before the
        emission loop - a distinct path from an empty imports list.
        """
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(0, [_UNKNOWN]),
                                 _entry(1, ["yet_another"])])]))
        assert _entry_issues(issues) == []

    def test_dropped_entry_is_excluded_from_invalid_entry_count(self):
        """
        The `continue` precedes the append, so a dropped entry is invisible
        in every respect - not merely unreported, but uncounted. A consumer
        reading invalid_entry_count cannot tell that anything was skipped.
        """
        issues = validate_imports(_internal([_descriptor(imports=[
            _entry(0, ["ordinal_zero"]),
            _entry(1, [_UNKNOWN]),
            _entry(2, ["name_empty"]),
        ])]))
        details = _entry_issues(issues)
        assert [d["entry_index"] for d in details] == [0, 2]
        assert all(d["invalid_entry_count"] == 2 for d in details), (
            "the unknown entry must not inflate the count either")

    def test_clean_entries_and_unknown_entries_are_indistinguishable(self):
        """
        An entry with no errors and an entry with only unknown errors produce
        identical output. This is the property that makes the drop dangerous,
        and the reason the tag-contract check exists upstream.
        """
        with_unknown = validate_imports(_internal([
            _descriptor(imports=[_entry(0, [_UNKNOWN])])]))
        with_clean = validate_imports(_internal([
            _descriptor(imports=[_entry(0, [])])]))
        assert with_unknown == with_clean == []


# =================================================================
# Rescue: a known tag anywhere on the entry
# =================================================================

class TestKnownTagRescuesTheEntry:
    """
    _first_matching scans the PRIORITY list, not the entry's error list, so
    order within the entry is irrelevant - one recognised tag is enough.
    """

    @pytest.mark.parametrize("errors,expected", [
        ([_UNKNOWN, "ordinal_zero"], "ordinal_zero"),
        (["ordinal_zero", _UNKNOWN], "ordinal_zero"),
        ([_UNKNOWN, "name_empty", "another_unknown"], "name_empty"),
    ])
    def test_known_tag_wins_regardless_of_position(self, errors, expected):
        issues = validate_imports(_internal([
            _descriptor(imports=[_entry(0, errors)])]))
        details = _entry_issues(issues)
        assert len(details) == 1
        assert details[0]["sub_reason"] == expected

    def test_priority_still_applies_among_known_tags(self):
        """An unknown tag does not disturb the ordering of the known ones."""
        issues = validate_imports(_internal([
            _descriptor(imports=[
                _entry(0, [_UNKNOWN, "name_empty", "ordinal_zero"])])]))
        assert _entry_issues(issues)[0]["sub_reason"] == "ordinal_zero"


# =================================================================
# Interaction with the emission cap
# =================================================================

class TestInteractionWithCap:

    def test_dropped_entries_do_not_consume_cap_budget(self):
        """
        Because the drop happens during collection, unknown entries never
        reach the capped slice - so a table padded with unknown tags cannot
        squeeze out reportable ones.
        """
        n = _MAX_ENTRY_ISSUES_PER_DESCRIPTOR
        imports = []
        for i in range(n):
            imports.append(_entry(len(imports), [_UNKNOWN]))
            imports.append(_entry(len(imports), ["ordinal_zero"]))
        issues = validate_imports(_internal([_descriptor(imports=imports)]))
        details = _entry_issues(issues)
        assert len(details) == n
        assert all(d["sub_reason"] == "ordinal_zero" for d in details)
        assert all(d["invalid_entry_count"] == n for d in details)


# =================================================================
# Descriptor level uses the inverse shape
# =================================================================

class TestDescriptorLevelUnknown:
    """
    _validate_descriptors tests `if reason != "unknown"` rather than
    `continue`-ing, so an unrecognised descriptor tag is also dropped - but
    via a different code shape. Pinned here so both are covered.
    """

    def test_unknown_descriptor_tag_emits_nothing(self):
        issues = validate_imports(_internal([
            _descriptor(errors=[_UNKNOWN])]))
        assert issues == []

    def test_unknown_descriptor_tag_does_not_block_entry_reporting(self):
        """The two levels are independent: a dropped descriptor tag must not
        suppress a reportable entry beneath it."""
        issues = validate_imports(_internal([
            _descriptor(errors=[_UNKNOWN],
                        imports=[_entry(0, ["ordinal_zero"])])]))
        details = _entry_issues(issues)
        assert len(details) == 1
        assert details[0]["sub_reason"] == "ordinal_zero"
