from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def validate_signature(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    has_sig = bool(metadata.get("has_signature"))
    sigs = metadata.get("signatures") or []

    if has_sig and not sigs:
        issues.append(StructuralIssue(
            issue=ReasonCodes.SIGNATURE_FLAG_SET_BUT_NO_METADATA,
            details={},
        ))

    return issues
