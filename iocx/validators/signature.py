# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue
from iocx.schemas.public_metadata import PublicMetadata
from iocx.schemas.analysis import AnalysisDict
from .decorators import depends_on


@depends_on("metadata", "analysis")
def validate_signature(metadata: PublicMetadata, analysis: AnalysisDict) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    has_sig = bool(metadata.get("has_signature"))
    sigs = metadata.get("signatures") or []

    # ---------------------------------------------------------
    # 1) Flag/metadata symmetry
    # ---------------------------------------------------------
    if has_sig and not sigs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_FLAG_SET_BUT_NO_METADATA,
            details={},
        ))
        return issues

    if not has_sig and sigs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_PRESENT_BUT_FLAG_NOT_SET,
            details={"count": len(sigs)},
        ))
        # Continue validating the certificates anyway

    if not sigs:
        return issues

    # ---------------------------------------------------------
    # 2) Multiplicity
    # ---------------------------------------------------------
    if len(sigs) > 1:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_MULTIPLE_CERTIFICATES,
            details={"count": len(sigs)},
        ))

    # ---------------------------------------------------------
    # 3) Certificate sanity checks
    # ---------------------------------------------------------
    file_size = analysis.get("file_size")
    sections = analysis.get("sections", []) or []
    overlay_offset = analysis.get("overlay_offset")

    for sig in sigs:
        offset = sig.get("file_offset")
        size = sig.get("length")
        revision = sig.get("revision")
        cert_type = sig.get("certificate_type")

        # Skip malformed metadata
        if not isinstance(offset, int) or not isinstance(size, int):
            continue

        # Length sanity
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

        # ---------------------------------------------------------
        # 4) Bounds checks
        # ---------------------------------------------------------
        if isinstance(file_size, int):
            if offset < 0 or offset + size > file_size:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.SIGNATURE_OUT_OF_FILE_BOUNDS,
                    details={"offset": offset, "length": size, "file_size": file_size},
                ))
                continue

        # Overlay check
        if isinstance(overlay_offset, int) and offset < overlay_offset < offset + size:
            issues.append(StructuralIssue(
                issue=ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA,
                details={"offset": offset, "length": size, "overlay_offset": overlay_offset},
            ))

        # Section overlap check
        for sec in sections:
            raw = sec.get("raw_address")
            raw_size = sec.get("raw_size")
            if isinstance(raw, int) and isinstance(raw_size, int):
                if max(offset, raw) < min(offset + size, raw + raw_size):
                    issues.append(StructuralIssue(
                        issue=ReasonCodes.SIGNATURE_OVERLAPS_OTHER_DATA,
                        details={"offset": offset, "length": size, "section": sec.get("name")},
                    ))
                    break

    return issues
