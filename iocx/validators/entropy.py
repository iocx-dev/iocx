from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue

HIGH_ENTROPY_THRESHOLD = 7.5
MIN_SECTION_SIZE_FOR_ENTROPY = 1024
MIN_OVERLAY_SIZE_FOR_ENTROPY = 1024
UNIFORM_STDDEV_THRESHOLD = 0.15 # very tight to stay conservative


def validate_entropy(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []
    sections: List[Dict[str, Any]] = analysis.get("sections", []) or []

    entropies: List[float] = []

    # --- Per-section high entropy ---
    for sec in sections:
        name = sec.get("name") or ""
        entropy = sec.get("entropy")
        raw_size = sec.get("raw_size")

        if not isinstance(entropy, (int, float)) or not isinstance(raw_size, int):
            continue

        e = float(entropy)

        if raw_size >= MIN_SECTION_SIZE_FOR_ENTROPY:
            entropies.append(e)

            if e >= HIGH_ENTROPY_THRESHOLD:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.ENTROPY_HIGH_SECTION,
                    details={
                        "section": name,
                        "entropy": e,
                        "raw_size": raw_size,
                    },
                ))

    # --- Overlay entropy (if overlay exists) ---
    overlay_info = analysis.get("overlay")

    if isinstance(overlay_info, dict):
        ov_entropy = overlay_info.get("entropy")
        ov_size = overlay_info.get("size")

        if isinstance(ov_entropy, (int, float)) and isinstance(ov_size, int):
            e = float(ov_entropy)
            if ov_size >= MIN_OVERLAY_SIZE_FOR_ENTROPY and e >= HIGH_ENTROPY_THRESHOLD:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.ENTROPY_HIGH_OVERLAY,
                    details={
                        "entropy": e,
                        "size": ov_size,
                    },
                ))

    # --- Uniform entropy pattern across sections ---
    if len(entropies) >= 2:
        mean = sum(entropies) / len(entropies)
        var = sum((e - mean) ** 2 for e in entropies) / len(entropies)
        stddev = var ** 0.5

        # Very conservative: only flag if everything is tightly clustered and high
        if mean >= HIGH_ENTROPY_THRESHOLD and stddev <= UNIFORM_STDDEV_THRESHOLD:
            issues.append(StructuralIssue(
                issue=ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS,
                details={
                    "mean_entropy": mean,
                    "stddev_entropy": stddev,
                    "count": len(entropies),
                },
            ))

    return issues
