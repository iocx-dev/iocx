# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0
"""
Coverage for the public projection of version_info_struct.

The projection is the last thing between an attacker-controlled resource
and public output, so the tests below lean on the two properties that
matter there: output size never scales with input size, and no key name
or character reaches the default payload unless it was explicitly
allowed.

All expectations were verified against the implementation.
"""

import pytest

from iocx.parsers.version_info_projection import (
    project_version_info,
    _clean,
    _dotted_version,
    _error_total,
    _DEFAULT_KEYS,
    _MAX_PUBLIC_TABLES,
    _MAX_PUBLIC_STRINGS_PER_TABLE,
    _MAX_PUBLIC_TRANSLATIONS,
    _MAX_PUBLIC_KEY,
    _MAX_PUBLIC_STRING,
)


# =====================================================================
# Builders
# =====================================================================

def _struct(tables=None, translations=None, **kw):
    """Minimal version_info_struct with the shape the projection expects."""
    vi = {
        "decoded": True,
        "errors": [],
        "fixed_file_info": {
            "file_version": (0x000A0000, 0x65F42308),
            "product_version": (0x000A0000, 0x65F42308),
        },
        "string_file_info": [{"errors": [], "tables": tables or []}],
        "var_file_info": [{
            "errors": [],
            "vars": [{"key": "Translation",
                      "translations": translations
                      if translations is not None
                      else [{"lang": 0x0409, "codepage": 0x04B0}]}],
        }],
    }
    vi.update(kw)
    return vi


def _table(lang="040904B0", strings=None, errors=None):
    return {"lang_codepage": lang,
            "strings": strings if strings is not None else {},
            "errors": errors or []}


_GOOD_STRINGS = {
    "CompanyName": "MalX Labs",
    "FileDescription": "IOCX test fixture",
    "OriginalFilename": "FIXTURE.EXE",
}


# =====================================================================
# Absence contract
# =====================================================================

def test_none_projects_to_none():
    """
    None means the binary carries no RT_VERSION resource. Because the
    parse now runs on every file regardless of analysis level, this has
    exactly one meaning and can never mean "this mode did not look".
    """
    assert project_version_info(None) is None


def test_tombstone_is_projected_not_discarded():
    """
    A resource that exists but cannot be trusted must stay visible.
    `decoded` plus `structural_error_count` are how a consumer tells a
    tombstone apart from a healthy blob.
    """
    out = project_version_info({
        "decoded": False,
        "errors": ["leaf_placement_implausible"],
        "fixed_file_info": None,
        "string_file_info": [],
        "var_file_info": [],
    })

    assert out is not None
    assert out["decoded"] is False
    assert out["structural_error_count"] == 1
    assert out["file_version"] is None
    assert out["tables"] == []


def test_empty_dict_is_not_treated_as_absence():
    """
    `if vi is None` rather than `if not vi`: an empty struct is a
    degenerate blob, not a missing resource, and must still project.
    """
    out = project_version_info({})
    assert out is not None
    assert out["decoded"] is False
    assert out["tables"] == []


# =====================================================================
# Version rendering
# =====================================================================

def test_dotted_version_splits_both_dwords():
    """MS = (major << 16) | minor; LS = (build << 16) | revision."""
    out = project_version_info(_struct())
    assert out["file_version"] == "10.0.26100.8968"
    assert out["product_version"] == "10.0.26100.8968"


@pytest.mark.parametrize("pair", [
    None,
    (1,),                       # wrong arity
    (1, 2, 3),
    ("a", 1),                   # non-int
    (1, "b"),
    (-1, 0),                    # negative
    (0, -1),
    (0x1_0000_0000, 0),         # wider than a DWORD
    (0, 0x1_0000_0000),
    "10.0.0.1",                 # already-rendered string
])
def test_dotted_version_rejects_malformed_pairs(pair):
    """
    A malformed pair yields None rather than a partially-derived string:
    a wrong version number is worse than an absent one.
    """
    out = project_version_info(_struct(
        fixed_file_info={"file_version": pair, "product_version": pair}))
    assert out["file_version"] is None
    assert out["product_version"] is None


def test_non_dict_ffi_does_not_raise():
    """A malformed struct must degrade, not propagate a TypeError."""
    for bad in (None, [], "x", 42):
        out = project_version_info(_struct(fixed_file_info=bad))
        assert out["file_version"] is None


# =====================================================================
# Sanitisation
# =====================================================================

def test_bidi_and_control_characters_are_stripped():
    """
    A bidi override in CompanyName renders text backwards in a terminal
    or dashboard - the filename-spoofing trick arriving through a field
    nobody inspects. Newlines break line-oriented consumers.
    """
    out = project_version_info(_struct(tables=[_table(strings={
        "CompanyName": "MalX \u202eLabs\u202c\nInc\tX",
    })]))
    assert out["tables"][0]["strings"]["CompanyName"] == "MalX LabsIncX"


@pytest.mark.parametrize("raw", [
    "\x00", "\x1b[31m", "\x7f", "\u202a", "\u202e", "\u2066", "\u2069",
    "\n", "\r", "\t",
])
def test_each_unsafe_character_class_is_removed(raw):
    assert raw not in (_clean(f"A{raw}B") or "")


def test_clean_rejects_non_strings():
    """A malformed struct cannot inject a non-string into public output."""
    for bad in (None, 42, [], {}, b"bytes"):
        assert _clean(bad) is None


def test_value_length_is_bounded():
    out = project_version_info(_struct(tables=[_table(
        strings={"CompanyName": "A" * (_MAX_PUBLIC_STRING + 500)})]))
    assert len(out["tables"][0]["strings"]["CompanyName"]) == _MAX_PUBLIC_STRING


def test_key_length_is_bounded_separately():
    long_key = "C" * (_MAX_PUBLIC_KEY + 50)
    out = project_version_info(
        _struct(tables=[_table(strings={long_key: "v"})]), full=True)
    projected = list(out["tables"][0]["strings"])
    assert all(len(k) <= _MAX_PUBLIC_KEY for k in projected)


def test_key_that_cleans_to_empty_is_dropped():
    """A control-character-only key would otherwise become "" in output."""
    out = project_version_info(
        _struct(tables=[_table(strings={"\x00\x01": "v",
                                        "CompanyName": "MalX"})]),
        full=True)
    assert "" not in out["tables"][0]["strings"]
    assert out["tables"][0]["strings"]["CompanyName"] == "MalX"


def test_non_string_value_becomes_empty_string_not_none():
    """`_clean(v) or ""` - the key survives, the value degrades to ""."""
    out = project_version_info(
        _struct(tables=[_table(strings={"CompanyName": 12345})]))
    assert out["tables"][0]["strings"]["CompanyName"] == ""


# =====================================================================
# Closed key set
# =====================================================================

def test_default_projection_emits_only_shortlist_keys():
    """
    StringFileInfo keys are arbitrary strings from the file. The default
    payload must not let a binary choose its own key NAMES, only values.
    """
    strings = dict(_GOOD_STRINGS)
    strings["EvilKey\u202e"] = "attacker chosen"
    strings["Comments"] = "not in the shortlist"

    out = project_version_info(_struct(tables=[_table(strings=strings)]))
    projected = set(out["tables"][0]["strings"])

    assert projected <= _DEFAULT_KEYS
    assert "Comments" not in projected
    assert "keys_filtered" in out["truncated"]


def test_full_projection_opens_the_key_set():
    strings = dict(_GOOD_STRINGS)
    strings["Comments"] = "now allowed"

    out = project_version_info(_struct(tables=[_table(strings=strings)]),
                               full=True)
    projected = out["tables"][0]["strings"]

    assert projected["Comments"] == "now allowed"
    assert "keys_filtered" not in out["truncated"]


def test_keys_filtered_not_flagged_when_nothing_is_dropped():
    out = project_version_info(_struct(tables=[_table(strings=_GOOD_STRINGS)]))
    assert "keys_filtered" not in out["truncated"]
    assert set(out["tables"][0]["strings"]) == set(_GOOD_STRINGS)


# =====================================================================
# Per-table separation
# =====================================================================

def test_tables_stay_separate_so_keys_do_not_collide():
    """
    A flat merge would let a key present in two language blocks overwrite
    itself, with the survivor decided by walk order - and a disagreement
    between blocks is itself a repackaging signal.
    """
    out = project_version_info(_struct(tables=[
        _table("040904B0", {"CompanyName": "Block A"}),
        _table("040704B0", {"CompanyName": "Block B"}),
    ]))

    assert len(out["tables"]) == 2
    assert out["tables"][0]["strings"]["CompanyName"] == "Block A"
    assert out["tables"][1]["strings"]["CompanyName"] == "Block B"


def test_languages_are_deduped_but_tables_are_not():
    """Two blocks may legitimately share a lang_codepage."""
    out = project_version_info(_struct(tables=[
        _table("040904B0", {"CompanyName": "A"}),
        _table("040904B0", {"CompanyName": "B"}),
    ]))
    assert out["languages"] == ["040904B0"]
    assert len(out["tables"]) == 2


def test_language_order_is_preserved():
    out = project_version_info(_struct(tables=[
        _table("080904B0"), _table("040904B0"), _table("080904B0"),
    ]))
    assert out["languages"] == ["080904B0", "040904B0"]


# =====================================================================
# Bounds - output must not scale with input
# =====================================================================

def test_table_cap_is_inclusive():
    """Exactly _MAX_PUBLIC_TABLES must not be refused."""
    out = project_version_info(_struct(
        tables=[_table(f"{i:04X}04B0") for i in range(_MAX_PUBLIC_TABLES)]))
    assert len(out["tables"]) == _MAX_PUBLIC_TABLES
    assert "tables" not in out["truncated"]


def test_table_cap_bounds_a_hostile_blob():
    """
    _decode_string_file_info advances by t_len >= 6, so a 1 MB blob can
    yield ~174k tables. Without the cap, output scales with input.
    """
    out = project_version_info(_struct(
        tables=[_table(f"{i:04X}04B0") for i in range(5_000)]))
    assert len(out["tables"]) == _MAX_PUBLIC_TABLES
    assert "tables" in out["truncated"]


def test_output_size_does_not_scale_with_table_count():
    """The property that matters downstream."""
    import json

    def sized(n):
        return len(json.dumps(project_version_info(_struct(
            tables=[_table(f"{i:04X}04B0", dict(_GOOD_STRINGS))
                    for i in range(n)]))))

    assert sized(500) == sized(50_000)


def test_strings_cap_is_inclusive():
    strings = {f"K{i}": "v" for i in range(_MAX_PUBLIC_STRINGS_PER_TABLE)}
    out = project_version_info(_struct(tables=[_table(strings=strings)]),
                               full=True)
    assert len(out["tables"][0]["strings"]) == _MAX_PUBLIC_STRINGS_PER_TABLE
    assert "strings" not in out["truncated"]


def test_strings_cap_bounds_a_hostile_table():
    strings = {f"K{i}": "v" for i in range(5_000)}
    out = project_version_info(_struct(tables=[_table(strings=strings)]),
                               full=True)
    assert len(out["tables"][0]["strings"]) == _MAX_PUBLIC_STRINGS_PER_TABLE
    assert "strings" in out["truncated"]


def test_translation_cap_is_inclusive():
    tr = [{"lang": i, "codepage": 0x04B0}
          for i in range(_MAX_PUBLIC_TRANSLATIONS)]
    out = project_version_info(_struct(translations=tr))
    assert len(out["translations"]) == _MAX_PUBLIC_TRANSLATIONS
    assert "translations" not in out["truncated"]


def test_translation_cap_bounds_a_hostile_var_block():
    tr = [{"lang": i, "codepage": 0x04B0} for i in range(1_000)]
    out = project_version_info(_struct(translations=tr))
    assert len(out["translations"]) == _MAX_PUBLIC_TRANSLATIONS
    assert "translations" in out["truncated"]


def test_truncation_flags_appear_at_most_once():
    strings = {f"K{i}": "v" for i in range(200)}
    out = project_version_info(_struct(
        tables=[_table(f"{i:04X}04B0", strings) for i in range(50)]),
        full=True)
    for tag in out["truncated"]:
        assert out["truncated"].count(tag) == 1


def test_clean_input_carries_no_truncation_flags():
    out = project_version_info(_struct(tables=[_table(strings=_GOOD_STRINGS)]))
    assert out["truncated"] == []


# =====================================================================
# Translations
# =====================================================================

def test_translations_render_as_eight_hex_chars():
    out = project_version_info(_struct(
        translations=[{"lang": 0x0409, "codepage": 0x04B0}]))
    assert out["translations"] == ["040904B0"]


def test_translations_are_deduped():
    out = project_version_info(_struct(
        translations=[{"lang": 0x0409, "codepage": 0x04B0}] * 5))
    assert out["translations"] == ["040904B0"]


@pytest.mark.parametrize("bad", [
    {"lang": -1, "codepage": 0},
    {"lang": 0x10000, "codepage": 0},
    {"lang": 0, "codepage": -1},
    {"lang": 0, "codepage": 0x10000},
    {"lang": "0409", "codepage": 0x04B0},
    {"lang": 0x0409},
    {},
])
def test_out_of_range_translations_are_skipped(bad):
    out = project_version_info(_struct(
        translations=[bad, {"lang": 0x0409, "codepage": 0x04B0}]))
    assert out["translations"] == ["040904B0"]


# =====================================================================
# Structural error count
# =====================================================================

def test_error_count_sums_every_level():
    """
    The top-level list alone is not enough: a blob whose envelope decoded
    cleanly but whose string tables are malformed would otherwise report
    decoded=True with a zero count, reading as healthy when it is not.
    """
    vi = {
        "decoded": True,
        "errors": ["top"],
        "string_file_info": [{
            "errors": ["sfi"],
            "tables": [{"lang_codepage": "040904B0", "strings": {},
                        "errors": ["tbl_a", "tbl_b"]}],
        }],
        "var_file_info": [{"errors": ["var"], "vars": []}],
    }
    assert project_version_info(vi)["structural_error_count"] == 5


def test_nested_errors_alone_are_still_counted():
    """decoded=True with a malformed table must not read as healthy."""
    out = project_version_info(_struct(
        tables=[_table(strings=_GOOD_STRINGS, errors=["lang_codepage_key"])]))
    assert out["decoded"] is True
    assert out["structural_error_count"] == 1


def test_error_total_tolerates_malformed_containers():
    for bad in ("string", 42, None):
        assert _error_total({"string_file_info": [bad],
                             "var_file_info": [bad]}) == 0


# =====================================================================
# Robustness against a malformed struct
# =====================================================================

@pytest.mark.parametrize("field, value", [
    ("string_file_info", "not a list"),
    ("string_file_info", [None, 42, "x"]),
    ("string_file_info", [{"tables": "not a list"}]),
    ("string_file_info", [{"tables": [None, 42]}]),
    ("string_file_info", [{"tables": [{"strings": "not a dict"}]}]),
    ("var_file_info", "not a list"),
    ("var_file_info", [None, 42]),
    ("var_file_info", [{"vars": "not a list"}]),
    ("var_file_info", [{"vars": [None, 42]}]),
    ("var_file_info", [{"vars": [{"translations": "not a list"}]}]),
    ("var_file_info", [{"vars": [{"translations": [None, "x", 42]}]}]),
])
def test_malformed_containers_do_not_raise(field, value):
    """
    Every nested container is type-checked before use, so a malformed
    struct yields empty output rather than a TypeError mid-projection.
    """
    out = project_version_info(_struct(**{field: value}))
    assert isinstance(out["tables"], list)
    assert isinstance(out["translations"], list)


def test_missing_keys_throughout_do_not_raise():
    assert project_version_info({"decoded": True}) is not None


# =====================================================================
# Output contract
# =====================================================================

def test_projection_has_a_stable_key_set():
    """The public shape must not vary with input, or consumers break."""
    expected = {
        "file_version", "product_version", "tables", "languages",
        "translations", "decoded", "structural_error_count", "truncated",
    }
    assert set(project_version_info(_struct())) == expected
    assert set(project_version_info({})) == expected
    assert set(project_version_info(_struct(), full=True)) == expected


def test_projection_is_json_serialisable():
    import json
    json.dumps(project_version_info(_struct(tables=[
        _table(strings={"CompanyName": "\u00a9 MalX \u202eLabs"})])))


def test_projection_does_not_mutate_the_input():
    vi = _struct(tables=[_table(strings=dict(_GOOD_STRINGS))])
    import copy
    before = copy.deepcopy(vi)
    project_version_info(vi)
    assert vi == before


def test_decoded_is_always_a_bool():
    """`bool(...)` - a truthy non-bool must not leak into public output."""
    for raw in (1, "yes", [1], None, 0, ""):
        assert isinstance(project_version_info({"decoded": raw})["decoded"],
                          bool)


def test_key_padding_cannot_suppress_the_shortlist():
    """
    Filtering happens before the cap is counted, so a table padded with
    junk keys cannot push the triage fields out of default output.
    Before that change, 64 junk keys ahead of CompanyName suppressed it
    entirely - and OriginalFilename versus the on-disk name is exactly
    the check that matters most on a suspicious file.
    """
    strings = {f"Junk{i}": "x" for i in range(_MAX_PUBLIC_STRINGS_PER_TABLE)}
    strings["CompanyName"] = "Microsoft Corporation"
    strings["OriginalFilename"] = "NOTEPAD.EXE"

    out = project_version_info(_struct(tables=[_table(strings=strings)]))

    assert out["tables"][0]["strings"] == {
        "CompanyName": "Microsoft Corporation",
        "OriginalFilename": "NOTEPAD.EXE",
    }
    assert "keys_filtered" in out["truncated"]
    assert "strings" not in out["truncated"]


def test_ordering_no_longer_decides_what_survives():
    """The same keys in either order must project identically."""
    junk = {f"Junk{i}": "x" for i in range(_MAX_PUBLIC_STRINGS_PER_TABLE)}
    real = {"CompanyName": "Microsoft Corporation",
    "OriginalFilename": "NOTEPAD.EXE"}

    junk_first = project_version_info(_struct(tables=[_table(strings={**junk, **real})]))
    real_first = project_version_info(_struct(tables=[_table(strings={**real, **junk})]))

    assert junk_first["tables"] == real_first["tables"]
