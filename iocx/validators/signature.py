# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Validate the WIN_CERTIFICATE (Authenticode) directory.

v0.7.6 migration: this validator now sources per-certificate structural
truth from the deterministic ``certificate_struct`` produced by
parser pe_certificates (read from InternalMetadata), rather than from
pefile's ``metadata["signatures"]`` list. The flag/metadata symmetry check
still consults the public ``has_signature`` flag, and the overlay / section
overlap checks still use the ``analysis`` geometry, so ALL existing checks
and reason codes are preserved.

Two v0.7.6 reason codes are added, in territory the existing checks did not
cover (no double-counting):

  CERTIFICATE_TABLE_MALFORMED     - structural decode failure / truncation
                                    reported by the parser. Distinct from the
                                    field-value checks (SIGNATURE_INVALID_*),
                                    which continue to own length/revision/type.
  CERTIFICATE_OFFSET_INSIDE_IMAGE - table-level "offset must lie outside the
                                    image" invariant, driven by the parser's
                                    `overlaps_image` fact (offset < end of any
                                    section's on-disk raw data).

Preserved reason codes:
  SIGNATURE_FLAG_SET_BUT_NO_METADATA
  SIGNATURE_PRESENT_BUT_FLAG_NOT_SET
  SIGNATURE_MULTIPLE_CERTIFICATES
  SIGNATURE_INVALID_LENGTH
  SIGNATURE_INVALID_REVISION
  SIGNATURE_INVALID_TYPE
  SIGNATURE_OUT_OF_FILE_BOUNDS
  SIGNATURE_OVERLAPS_OTHER_DATA
"""

from typing import Dict, Any, List

from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.internal_schema import InternalMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on

# Parser per-certificate error tags that indicate a genuine structural decode
# failure (as opposed to a bad field VALUE, which the SIGNATURE_INVALID_*
# checks below already own). Kept deliberately narrow to avoid double-counting.
_STRUCTURAL_CERT_ERROR_TAGS = {
    "length_too_small",  # also covered by SIGNATURE_INVALID_LENGTH; see note
}


@depends_on("internal", "metadata", "analysis")
def validate_signature(internal: InternalMetadata,
                       metadata: PublicMetadata,
                       analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    cert_struct = internal.get("certificate_struct")

    # ---------------------------------------------------------
    # Structural decode failure takes precedence:
    # The parser returns a struct (not None) when a security directory is
    # declared. If it could not decode that directory at all, report it as
    # malformed FIRST, otherwise the empty `certificates` list would trip
    # the symmetry check below and mis-report a broken directory as
    # "flag set but no metadata". Distinct from the field-value checks
    # (SIGNATURE_INVALID_*), which own length/revision/type.
    # ---------------------------------------------------------
    if cert_struct is not None and cert_struct.get("errors"):
        issues.append(StructuralIssue(
            issue=ReasonCodes.CERTIFICATE_TABLE_MALFORMED,
            details={"sub_reason": "top_level_decode",
                     "errors": list(cert_struct["errors"])},
        ))
        return issues

    # Deterministic presence: the parser returns None when there is no
    # security directory. This replaces the pefile `signatures` list as the
    # source of "were any certificates actually parsed".
    certs: List[Dict[str, Any]] = (
        cert_struct.get("certificates", []) if cert_struct else []
    ) or []
    present = bool(certs)

    has_sig = bool(metadata.get("has_signature"))

    # ---------------------------------------------------------
    # 1) Flag/metadata symmetry
    # ---------------------------------------------------------
    if has_sig and not present:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_FLAG_SET_BUT_NO_METADATA,
            details={},
        ))
        return issues

    if not has_sig and present:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_PRESENT_BUT_FLAG_NOT_SET,
            details={"count": len(certs)},
        ))
        # Continue validating the certificates anyway (preserved behaviour)

    if cert_struct is None:
        return issues

    # ---------------------------------------------------------
    # 1a) Table truncation
    # ---------------------------------------------------------
    for tag in cert_struct.get("truncations", []) or []:
        issues.append(StructuralIssue(
            issue=ReasonCodes.CERTIFICATE_TABLE_MALFORMED,
            details={"sub_reason": "truncation", "region": tag},
        ))

    # ---------------------------------------------------------
    # 1b) Table offset must lie OUTSIDE the mapped image
    # CERTIFICATE_OFFSET_INSIDE_IMAGE: Table-level invariant from
    # the parser's overlaps_image fact. This is a different owner from the
    # per-certificate section-overlap check in step 4 (which is byte-range,
    # per-section); both may co-fire on a pathological sample. Kept
    # separate to preserve the existing check while meeting the spec.
    # ---------------------------------------------------------
    if cert_struct.get("overlaps_image") is True:
        issues.append(StructuralIssue(
            issue=ReasonCodes.CERTIFICATE_OFFSET_INSIDE_IMAGE,
            details={"offset": cert_struct.get("offset"),
                     "size": cert_struct.get("size"),
                     "image_raw_end": cert_struct.get("image_raw_end")},
        ))

    # ---------------------------------------------------------
    # 2) Multiplicity
    # ---------------------------------------------------------
    if len(certs) > 1:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_MULTIPLE_CERTIFICATES,
            details={"count": len(certs)},
        ))

    # ---------------------------------------------------------
    # 3) Per-certificate field sanity
    # ---------------------------------------------------------
    # file_size: prefer the analysis value to preserve the original bounds
    # behaviour; fall back to the parser's file_size if analysis omits it.
    file_size = analysis.get("file_size")
    if not isinstance(file_size, int):
        fs = cert_struct.get("file_size")
        file_size = fs if isinstance(fs, int) else None
    sections = analysis.get("sections", []) or []
    overlay_offset = analysis.get("overlay_offset")

    for cert in certs:
        offset = cert.get("offset")          # absolute file offset
        size = cert.get("length")            # dwLength (incl. 8-byte header)
        revision = cert.get("revision")
        cert_type = cert.get("cert_type")

        # Skip malformed metadata (preserved guard)
        if not isinstance(offset, int) or not isinstance(size, int):
            continue

        # Length sanity: Owns the length<8 fact; we deliberately
        # do NOT also emit CERTIFICATE_TABLE_MALFORMED for the parser's
        # "length_too_small" tag, to avoid double-counting.
        if size < 8:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SIGNATURE_INVALID_LENGTH,
                details={"length": size},
            ))
            continue

        # Revision sanity
        if revision not in (0x0100, 0x0200):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SIGNATURE_INVALID_REVISION,
                details={"revision": revision},
            ))

        # Type sanity
        if cert_type not in (0x0001, 0x0002):
            issues.append(StructuralIssue(
                issue=ReasonCodes.SIGNATURE_INVALID_TYPE,
                details={"certificate_type": cert_type},
            ))

        # -----------------------------------------------------
        # 4) Bounds + overlap checks
        # -----------------------------------------------------
        if isinstance(file_size, int):
            if offset < 0 or offset + size > file_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS,
                    details={"offset": offset, "length": size,
                             "file_size": file_size},
                ))
                continue

        # Overlay check
        if isinstance(overlay_offset, int) and offset < overlay_offset < offset + size:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA,
                details={"offset": offset, "length": size,
                         "overlay_offset": overlay_offset},
            ))

        # Section overlap check
        for sec in sections:
            raw = sec.get("raw_address")
            raw_size = sec.get("raw_size")
            if isinstance(raw, int) and isinstance(raw_size, int):
                if max(offset, raw) < min(offset + size, raw + raw_size):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA,
                        details={"offset": offset, "length": size,
                                 "section": sec.get("name")},
                    ))
                    break

    return issues
