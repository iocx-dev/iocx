# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the export-table structure produced by parser_exports.

Absence of an export directory is NOT a structural defect — most EXEs
(as opposed to DLLs) legitimately have no exports. We only emit codes
when an export directory is present and structurally malformed.

Reason codes emitted:
  EXPORT_DIRECTORY_INVALID_HEADER
  EXPORT_DIRECTORY_OUT_OF_BOUNDS
  EXPORT_TABLE_TRUNCATED
  EXPORT_NAME_RVA_INVALID
  EXPORT_NAME_NOT_ASCII
  EXPORT_NAME_POINTER_TABLE_UNSORTED
  EXPORT_ORDINAL_OUT_OF_RANGE
  EXPORT_FORWARDER_MALFORMED
  EXPORT_FUNCTION_RVA_INVALID
  EXPORT_NAME_ORDINAL_INDEX_INVALID
"""

from typing import Any, Dict, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.public_metadata import PublicMetadata
from .decorators import depends_on


# Deterministic priority orders for mapping parser error tags to a single
# reason. The validator emits at most one issue per malformed entry per
# pathology class; the first tag in priority order wins.
_NAME_RVA_ERROR_PRIORITY = [
    "name_rva_missing",
    "name_rva_zero",
    "read_failed",
    "unterminated",
]

_NAME_ENCODING_ERROR_PRIORITY = [
    "non_ascii",
    "name_not_printable_ascii",
]


@depends_on("internal", "metadata")
def validate_exports(internal: InternalMetadata, metadata: PublicMetadata) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    exp = internal.get("export_struct")
    if exp is None:
        return issues

    opt = metadata.get("optional_header") or {}
    size_of_image = opt.get("size_of_image")

    # If the parser couldn't decode the header at all, the rest of the
    # validation can't run meaningfully.
    if exp.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "top_level_decode",
                     "errors": list(exp["errors"])},
        ))
        return issues

    _validate_placement(exp, size_of_image, issues)
    _validate_truncations(exp, issues)

    header = exp.get("header")
    if header is None:
        return issues

    _validate_header_consistency(exp, header, issues)
    _validate_name_pointers(exp, header, issues)
    _validate_functions(exp, header, size_of_image, issues)
    _validate_name_pointer_ordering(exp, issues)

    return issues


# =================================================================
# Placement
# =================================================================

def _validate_placement(exp, size_of_image, issues):
    """
    The export directory must lie within the PE image (SizeOfImage). We
    don't require it to lie in a specific section (exports can live
    anywhere in the image), but it must be within the image bounds.
    """
    rva = exp.get("rva")
    size = exp.get("size") or 0

    # Skip placement check if the metadata layer didn't populate
    # size_of_image. This shouldn't happen in normal operation. If it
    # does, an upstream bug needs investigating, not a placement issue.
    if rva is None or size_of_image is None:
        return

    if rva + size > size_of_image:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_OUT_OF_BOUNDS,
            details={"rva": rva, "size": size,
                     "size_of_image": size_of_image},
        ))


# =================================================================
# Truncations
# =================================================================

def _validate_truncations(exp: Dict[str, Any],
                          issues: List[StructuralIssue]) -> None:
    """
    Map parser truncation tags to a single reason code with structured
    details. Each tag becomes one issue so the consumer sees one issue
    per truncated table rather than a single bundled report.
    """
    for tag in exp.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_TABLE_TRUNCATED,
            details={"table": tag},
        ))


# =================================================================
# Header consistency
# =================================================================

def _validate_header_consistency(exp: Dict[str, Any],
                                 header: Dict[str, int],
                                 issues: List[StructuralIssue]) -> None:
    """
    Sanity-check declared counts against declared array RVAs.

    A non-zero NumberOfFunctions with AddressOfFunctions == 0 is
    structurally inconsistent: the EAT is declared to exist but has no
    location. Same logic for NumberOfNames / AddressOfNames /
    AddressOfNameOrdinals.

    Also flag NumberOfNames > NumberOfFunctions, which is impossible
    in a well-formed export table.
    """
    num_funcs = header.get("NumberOfFunctions", 0)
    num_names = header.get("NumberOfNames", 0)
    addr_funcs = header.get("AddressOfFunctions", 0)
    addr_names = header.get("AddressOfNames", 0)
    addr_name_ord = header.get("AddressOfNameOrdinals", 0)

    if num_funcs > 0 and addr_funcs == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "eat_rva_zero_with_nonzero_count",
                     "NumberOfFunctions": num_funcs},
        ))

    if num_names > 0 and addr_names == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "enpt_rva_zero_with_nonzero_count",
                     "NumberOfNames": num_names},
        ))

    if num_names > 0 and addr_name_ord == 0:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "eot_rva_zero_with_nonzero_count",
                     "NumberOfNames": num_names},
        ))

    if num_names > num_funcs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_DIRECTORY_INVALID_HEADER,
            details={"sub_reason": "num_names_exceeds_num_functions",
                     "NumberOfNames": num_names,
                     "NumberOfFunctions": num_funcs},
        ))


# =================================================================
# Name pointer table
# =================================================================

def _validate_name_pointers(exp: Dict[str, Any],
                            header: Dict[str, int],
                            issues: List[StructuralIssue]) -> None:
    """
    For each name pointer entry, emit at most one issue per pathology
    class:
      - one EXPORT_NAME_RVA_INVALID if the name RVA is unusable
      - one EXPORT_NAME_NOT_ASCII if the name decoded but is non-ASCII
      - one EXPORT_NAME_ORDINAL_INDEX_INVALID if the ordinal index is bad

    Priority orders in module-level constants determine which sub-reason
    wins when an entry carries multiple tags in the same class.
    """
    num_funcs = header.get("NumberOfFunctions", 0)

    for entry in exp.get("name_pointers", []) or []:
        index = entry.get("index")
        entry_errors = entry.get("errors", []) or []

        # ---- Name RVA validation: one issue per entry, priority-resolved ----
        rva_reason = _first_matching(entry_errors, _NAME_RVA_ERROR_PRIORITY)
        if rva_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_NAME_RVA_INVALID,
                details={"index": index,
                         "name_rva": entry.get("name_rva"),
                         "sub_reason": rva_reason},
            ))

        # ---- Name encoding: one issue per entry, priority-resolved ----
        encoding_reason = _first_matching(
            entry_errors, _NAME_ENCODING_ERROR_PRIORITY
        )
        if encoding_reason != "unknown":
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_NAME_NOT_ASCII,
                details={"index": index,
                         "name": entry.get("name"),
                         "sub_reason": encoding_reason},
            ))

        # ---- Ordinal index bounds ----
        if "ordinal_index_missing" in entry_errors:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_NAME_ORDINAL_INDEX_INVALID,
                details={"index": index,
                         "sub_reason": "missing"},
            ))
        elif "ordinal_index_out_of_range" in entry_errors:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_NAME_ORDINAL_INDEX_INVALID,
                details={"index": index,
                         "ordinal_index": entry.get("ordinal_index"),
                         "num_functions": num_funcs,
                         "sub_reason": "out_of_range"},
            ))


def _validate_name_pointer_ordering(exp: Dict[str, Any],
                                    issues: List[StructuralIssue]) -> None:
    """
    The PE spec requires the Export Name Pointer Table to be sorted
    lexicographically by name so that GetProcAddress can use binary search.
    Unsorted tables are a real malware pattern (some packers use them to
    confuse static analysers that assume sorted entries).
    """
    names: List[str] = []
    for entry in exp.get("name_pointers", []) or []:
        name = entry.get("name")
        # Skip ordering check if any name in the table is unreadable.
        # Reporting "unsorted" against a partial view is misleading; the
        # disorder might just be a downstream effect of the decode failures.
        # The per-entry EXPORT_NAME_RVA_INVALID / EXPORT_NAME_NOT_ASCII
        # codes already carry the signal that the table is malformed.
        if name is None or not entry.get("name_valid"):
            return
        names.append(name)

    if not names:
        return

    sorted_names = sorted(names)
    if names != sorted_names:
        # Report once per table, not per pair
        issues.append(StructuralIssue(
            issue=ReasonCodes.EXPORT_NAME_POINTER_TABLE_UNSORTED,
            details={"name_count": len(names),
                     "first_violation_index": _first_unsorted_index(names)},
        ))


def _first_unsorted_index(names: List[str]) -> int:
    """Return the index of the first name that violates ascending order."""
    for i in range(1, len(names)):
        if names[i] < names[i - 1]:
            return i
    return -1 # pragma: no cover - defensive; caller guarantees unsorted input


# =================================================================
# Function entries
# =================================================================

def _validate_functions(exp, header, size_of_image, issues):
    """
    For each function entry, check:
      - ordinal range fits in u16 (single max-ordinal check covers all entries)
      - address_rva, when non-zero and non-forwarder, points within image
      - forwarder strings, when present, conform to the spec format
    """
    base = header.get("Base", 0)
    num_funcs = header.get("NumberOfFunctions", 0)

    # Ordinal range sanity: Base + (NumberOfFunctions - 1) must fit in u16.
    # Some malware sets Base near 0xFFFF to push ordinals into an invalid
    # range while keeping the count plausible. The per-entry ordinal check
    # is redundant here. entry.ordinal is computed as Base + index by the
    # parser, so any entry-level overflow is implied by the max check.
    if num_funcs > 0:
        max_ordinal = base + num_funcs - 1
        if max_ordinal > 0xFFFF:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_ORDINAL_OUT_OF_RANGE,
                details={"sub_reason": "max_exceeds_u16",
                         "base": base,
                         "num_functions": num_funcs,
                         "max_ordinal": max_ordinal},
            ))

    for entry in exp.get("functions", []) or []:
        index = entry.get("index")
        ordinal = entry.get("ordinal")
        address_rva = entry.get("address_rva")

        if entry.get("is_forwarder"):
            forwarder = entry.get("forwarder")
            if forwarder is None:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.EXPORT_FORWARDER_MALFORMED,
                    details={"index": index, "ordinal": ordinal,
                             "sub_reason": "unreadable"},
                ))
            elif not entry.get("forwarder_valid"):
                issues.append(StructuralIssue(
                    issue=ReasonCodes.EXPORT_FORWARDER_MALFORMED,
                    details={"index": index, "ordinal": ordinal,
                             "forwarder": forwarder, "sub_reason": "format"},
                ))
            continue

        # An EAT entry of 0 means "this ordinal slot is unused" -> legal per spec
        if address_rva is None or address_rva == 0:
            continue

        # Otherwise the RVA must point within the image
        if size_of_image is not None and address_rva >= size_of_image:
            issues.append(StructuralIssue(
                issue=ReasonCodes.EXPORT_FUNCTION_RVA_INVALID,
                details={"index": index, "ordinal": ordinal,
                         "address_rva": address_rva,
                         "size_of_image": size_of_image,
                         "sub_reason": "exceeds_image"},
            ))


# =================================================================
# Helpers
# =================================================================

def _first_matching(errors: List[str], candidates: List[str]) -> str:
    """Return the first error tag from `candidates` that appears in `errors`."""
    for c in candidates:
        if c in errors:
            return c
    return "unknown"
