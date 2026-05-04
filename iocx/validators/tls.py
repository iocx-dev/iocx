from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue


def validate_tls(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []

    for entry in analysis.get("extended", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("value") != "tls_directory":
            continue

        meta = entry.get("metadata") or {}
        start = meta.get("start_address")
        end = meta.get("end_address")
        callbacks = meta.get("callbacks")

        if not isinstance(start, int) or not isinstance(end, int) or not isinstance(callbacks, int):
            continue

        if not (start <= callbacks < end):
            issues.append(StructuralIssue(
                issue=ReasonCodes.TLS_CALLBACK_OUTSIDE_RANGE,
                details={
                    "callbacks": callbacks,
                    "start_address": start,
                    "end_address": end,
                },
            ))

    return issues
