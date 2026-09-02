# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the version-info structure produced by parser_version_info.

Absence of RT_VERSION is NOT a structural defect — kernel drivers, MSI
custom-action DLLs and many cross-compiled binaries legitimately omit it.
We only emit structural codes when an RT_VERSION resource is present and
malformed.

Parser tombstone tags and where each is consumed
------------------------------------------------
The parser records faults in several lists at different levels, and the
level determines which branch here reads them:

  decoded is False -> the whole top-level `errors` list is forwarded by the
      "undecoded" branch:  leaf_struct_unpack, read_failed, too_short,
      header_unpack.

  decoded is True  -> the "undecoded" branch is skipped, so tags appended to
      the top-level list AFTER that point need their own consumers:
        * fixed_file_info_unpack / fixed_file_info_truncated, read by the
          FFI parse_failed branch via its startswith filter;
        * child_header_unpack / child_length_invalid / unknown_child, read
          by the child-dispatch branch below. Without it a blob carrying an
          unrecognised child, or a child whose wLength runs past the
          envelope, reports entirely clean.

  per-item lists   -> string_file_info[].errors, its tables[].errors, and
      var_file_info[].errors are each forwarded wholesale by their loops.
"""

from typing import Any, Dict, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


# Child-dispatch faults, priority-resolved. The first two each `break` the
# parser's walk, so at most one of them occurs and never both; the third
# does not break and may repeat. A walk-terminating fault is the more
# fundamental fact - it means the remaining children were never examined -
# so both precede unknown_child.
_CHILD_ERROR_PRIORITY = [
    "child_max_exceeded",
    "child_header_unpack",
    "child_length_invalid",
    "unknown_child",
]


@depends_on("internal", "analysis")
def validate_version_info(metadata: InternalMetadata,
                          analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    vi = metadata.get("version_info_struct")
    if vi is None:
        return issues  # no RT_VERSION present — not a defect

    sections = analysis.get("sections") or []
    rsrc_section = next(
        (s for s in sections if s["name"].lower() == ".rsrc"),
        None,
    )

    # ---- Placement within .rsrc ----
    if rsrc_section is not None and vi.get("rva") is not None:
        rsrc_va = rsrc_section["virtual_address"]
        rsrc_vs = rsrc_section["virtual_size"]
        rva = vi["rva"]
        size = vi["size"] or 0
        if not (rsrc_va <= rva and rva + size <= rsrc_va + rsrc_vs):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
                details={"sub_reason": "placement", "rva": rva, "size": size},
            ))

    # ---- Top-level header ----
    if not vi.get("decoded"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
            details={"sub_reason": "undecoded", "errors": vi.get("errors", [])},
        ))
        return issues  # nothing further to validate

    if not vi.get("header_ok"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
            details={"sub_reason": "szkey_mismatch"},
        ))
    if not vi.get("length_consistent"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
            details={"sub_reason": "length_inconsistent"},
        ))

    # ---- Child dispatch ----
    # These tags are appended to the top-level errors list AFTER `decoded`
    # is set, so the undecoded branch above has already been skipped and no
    # other branch reads them. Priority-resolved to one issue per blob; the
    # full matching set is carried in details, since unknown_child can
    # repeat and its count is the signal.
    vi_errors = vi.get("errors") or []
    child_reason = _first_matching(vi_errors, _CHILD_ERROR_PRIORITY)
    if child_reason != "unknown":
        issues.append(StructuralIssue(
            issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
            details={"sub_reason": child_reason,
                     "errors": [e for e in vi_errors
                                if e in _CHILD_ERROR_PRIORITY]},
        ))

    # ---- VS_FIXEDFILEINFO ----
    ffi = vi.get("fixed_file_info")
    if ffi is None:
        # Only flag if there were parse errors; some binaries legitimately
        # omit VS_FIXEDFILEINFO with wValueLength == 0.
        if any(e.startswith("fixed_file_info") for e in vi_errors):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO,
                details={"sub_reason": "parse_failed",
                         "errors": [e for e in vi_errors
                                    if e.startswith("fixed_file_info")]},
            ))
    else:
        if not ffi.get("signature_ok"):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO,
                details={"sub_reason": "signature",
                         "signature": ffi.get("signature")},
            ))
        if not ffi.get("struct_version_ok"):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_FIXEDINFO,
                details={"sub_reason": "struct_version",
                         "struct_version": ffi.get("struct_version")},
            ))

    # ---- StringFileInfo ----
    for sfi in vi.get("string_file_info", []):
        if sfi.get("errors"):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO,
                details={"errors": sfi["errors"],
                         "tables": len(sfi.get("tables", []))},
            ))
            continue
        for tbl in sfi.get("tables", []):
            if tbl.get("errors"):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO,
                    details={"errors": tbl["errors"],
                             "lang_codepage": tbl.get("lang_codepage")},
                ))

    # ---- VarFileInfo ----
    for vfi in vi.get("var_file_info", []):
        if vfi.get("errors"):
            issues.append(StructuralIssue(
                issue=ReasonCodes.RESOURCE_VERSIONINFO_INVALID_VARFILEINFO,
                details={"errors": vfi["errors"],
                         "vars": len(vfi.get("vars", []))},
            ))

    return issues


def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first tag from `candidates` present in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
