# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Public projection of ``version_info_struct``.

Deliberately a projection rather than a serialisation of the internal
struct:

  * version numbers become dotted quads, not (MS, LS) pairs;
  * string values are stripped of control and bidi characters;
  * string tables stay separate, so a key present in two language blocks
    with different values does not silently collapse to one;
  * the raw parser ``errors`` vocabulary stays internal - the public view
    carries a count, and the structural reason codes carry the detail;
  * every list is bounded, so output size does not scale with input size.

The default projection emits a CLOSED key set. StringFileInfo keys are
arbitrary strings taken from the file, so allowing them through unfiltered
would let a binary choose the key names in public output, not merely the
values. ``full=True`` opts into the open set.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# Control characters and bidi overrides are stripped from public string
# output. The parser bounds LENGTH and replacement-decodes invalid UTF-16,
# but leaves these in: a bidi override in CompanyName renders text
# backwards in a terminal or dashboard - the filename-spoofing trick,
# arriving through a field nobody inspects. ANSI escapes are the same
# class of problem for terminal consumers.
#
# \t \n \r are stripped too, unlike the usual "printable" allowance:
# these are single-line display fields, and a newline in CompanyName
# breaks line-oriented consumers and enables log injection.
_UNSAFE_CHARS = re.compile(
    r"[\x00-\x1f\x7f]"                        # all C0 controls, plus DEL
    r"|[\u202a-\u202e\u2066-\u2069]"          # bidi embedding / override
)

# A defensive second bound on public strings. The parser already caps
# values at 512 and keys at 128, so these only bite if that changes.
_MAX_PUBLIC_STRING = 512
_MAX_PUBLIC_KEY = 128

# Caps on public output. The parser bounds each value's length but not the
# NUMBER of tables, strings or translations: _decode_string_file_info
# advances by t_len >= 6, so a 1 MB blob can yield ~174k tables. Without
# these, output size scales with attacker-controlled input.
_MAX_PUBLIC_TABLES = 16
_MAX_PUBLIC_STRINGS_PER_TABLE = 64
_MAX_PUBLIC_TRANSLATIONS = 32

# Closed key set for the default projection: the fields that carry triage
# value and appear in essentially every well-formed binary.
_DEFAULT_KEYS = frozenset({
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
})


# =====================================================================
# Helpers
# =====================================================================

def _clean(text: Any, limit: int = _MAX_PUBLIC_STRING) -> Optional[str]:
    """
    Strip control and bidi characters from an attacker-controlled string.

    Returns None for anything that is not a str, so a malformed struct
    cannot inject a non-string into public output.
    """
    if not isinstance(text, str):
        return None
    return _UNSAFE_CHARS.sub("", text)[:limit]


def _dotted_version(pair: Any) -> Optional[str]:
    """
    Render a (MS, LS) DWORD pair as major.minor.build.revision.

    Each DWORD holds TWO 16-bit components:
        MS = (major << 16) | minor
        LS = (build << 16) | revision

    Emitting the raw pair makes every consumer re-derive this, and the
    word order is easy to get backwards.
    """
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        return None
    ms, ls = pair
    if not isinstance(ms, int) or not isinstance(ls, int):
        return None
    if ms < 0 or ls < 0 or ms > 0xFFFFFFFF or ls > 0xFFFFFFFF:
        return None
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _error_total(vi: Dict[str, Any]) -> int:
    """
    Count every parser error tag, at all levels.

    The top-level list alone is not enough: a blob whose envelope decoded
    cleanly but whose string tables carry lang_codepage_key or
    string_length would otherwise report decoded=True with a zero count,
    reading as healthy when it is not.
    """
    total = len(vi.get("errors") or [])

    for sfi in vi.get("string_file_info") or []:
        if not isinstance(sfi, dict):
            continue
        total += len(sfi.get("errors") or [])
        for table in sfi.get("tables") or []:
            if isinstance(table, dict):
                total += len(table.get("errors") or [])

    for vfi in vi.get("var_file_info") or []:
        if isinstance(vfi, dict):
            total += len(vfi.get("errors") or [])

    return total


def _flag(truncated: List[str], tag: str) -> None:
    """Record a truncation tag once, preserving first-seen order."""
    if tag not in truncated:
        truncated.append(tag)


def _project_tables(vi: Dict[str, Any],
                    full: bool,
                    truncated: List[str]) -> Tuple[List[Dict[str, Any]],
                                                   List[str]]:
    """
    Project the string tables, keeping each language block separate.

    A flat merge across tables would let a key present in two language
    blocks overwrite itself, with the survivor decided by walk order -
    and a disagreement between blocks is itself a repackaging signal.
    """
    tables: List[Dict[str, Any]] = []
    languages: List[str] = []

    for sfi in vi.get("string_file_info") or []:
        if not isinstance(sfi, dict):
            continue

        for table in sfi.get("tables") or []:
            if not isinstance(table, dict):
                continue

            if len(tables) >= _MAX_PUBLIC_TABLES:
                _flag(truncated, "tables")
                return tables, languages

            lang = _clean(table.get("lang_codepage"), _MAX_PUBLIC_KEY)
            if lang and lang not in languages:
                languages.append(lang)

            raw_strings = table.get("strings")
            if not isinstance(raw_strings, dict):
                raw_strings = {}

            # Filter and count in ONE pass, so neither the filtered-out
            # keys nor an intermediate list scales with input size. A
            # separate `candidates` list would be bounded only by the
            # parser's per-table string count, which is unbounded.
            strings: Dict[str, str] = {}
            kept = 0
            for k, v in raw_strings.items():
                key = _clean(k, _MAX_PUBLIC_KEY)
                if not key:
                    continue
                if not full and key not in _DEFAULT_KEYS:
                    _flag(truncated, "keys_filtered")
                    continue

                # Count only what is actually emitted: filtering before
                # counting stops a table padded with junk keys from
                # exhausting the cap ahead of the shortlist.
                if kept >= _MAX_PUBLIC_STRINGS_PER_TABLE:
                    _flag(truncated, "strings")
                    break

                strings[key] = _clean(v) or ""
                kept += 1

            tables.append({"lang_codepage": lang, "strings": strings})

    return tables, languages


def _project_translations(vi: Dict[str, Any],
                          truncated: List[str]) -> List[str]:
    """Render VarFileInfo translation pairs as 8-hex-char lang+codepage."""
    translations: List[str] = []

    for vfi in vi.get("var_file_info") or []:
        if not isinstance(vfi, dict):
            continue

        for var in vfi.get("vars") or []:
            if not isinstance(var, dict):
                continue

            for t in var.get("translations") or []:
                if not isinstance(t, dict):
                    continue

                lang = t.get("lang")
                cp = t.get("codepage")
                if not isinstance(lang, int) or not isinstance(cp, int):
                    continue
                if not (0 <= lang <= 0xFFFF) or not (0 <= cp <= 0xFFFF):
                    continue

                rendered = f"{lang:04X}{cp:04X}"
                if rendered in translations:
                    continue

                if len(translations) >= _MAX_PUBLIC_TRANSLATIONS:
                    _flag(truncated, "translations")
                    return translations

                translations.append(rendered)

    return translations


# =====================================================================
# Public API
# =====================================================================

def project_version_info(vi: Optional[Dict[str, Any]],
                         *, full: bool = False) -> Optional[Dict[str, Any]]:
    """
    Derive the public view of ``version_info_struct``.

    Returns None when no RT_VERSION resource is present, matching the
    parser's own contract. Because the parse now runs on every file
    regardless of analysis level, None has exactly one meaning - the
    binary carries no version-info - and can never mean "this mode did
    not look".

    A tombstoned struct (decoded=False, errors populated) is projected
    normally rather than discarded: a resource that exists but cannot be
    trusted must stay visible, and `decoded` plus
    `structural_error_count` are how a consumer tells the two apart.
    """
    if vi is None:
        return None

    ffi = vi.get("fixed_file_info")
    if not isinstance(ffi, dict):
        ffi = {}

    truncated: List[str] = []
    tables, languages = _project_tables(vi, full, truncated)
    translations = _project_translations(vi, truncated)

    return {
        "file_version": _dotted_version(ffi.get("file_version")),
        "product_version": _dotted_version(ffi.get("product_version")),
        "tables": tables,
        "languages": languages,
        "translations": translations,
        # Structural health, without exposing the tag vocabulary. The
        # matching RESOURCE_VERSIONINFO_* reason codes carry the detail.
        "decoded": bool(vi.get("decoded")),
        "structural_error_count": _error_total(vi),
        "truncated": truncated,
    }
