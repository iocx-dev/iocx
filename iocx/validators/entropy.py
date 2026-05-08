from typing import Dict, Any, List
from iocx.reason_codes import ReasonCodes
from iocx.validators.schema import StructuralIssue

HIGH_ENTROPY_THRESHOLD = 7.5
LOW_ENTROPY_THRESHOLD = 0.2
MIN_SECTION_SIZE_FOR_ENTROPY = 1024
MIN_SECTION_SIZE_FOR_LOW_ENTROPY = 16384 # 16 KB – very conservative
MIN_OVERLAY_SIZE_FOR_ENTROPY = 1024
UNIFORM_STDDEV_THRESHOLD = 0.15


def validate_entropy(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> List[StructuralIssue]:
    issues: List[StructuralIssue] = []
    sections: List[Dict[str, Any]] = analysis.get("sections", []) or []

    entropies: List[float] = []

    # ---------------------------------------------------------
    # 1) Per-section entropy checks
    # ---------------------------------------------------------
    for sec in sections:
        name = sec.get("name") or ""
        entropy = sec.get("entropy")
        raw_size = sec.get("raw_size")

        if not isinstance(entropy, (int, float)) or not isinstance(raw_size, int):
            continue

        e = float(entropy)

        if raw_size >= MIN_SECTION_SIZE_FOR_ENTROPY:
            entropies.append(e)

            # High entropy
            if e >= HIGH_ENTROPY_THRESHOLD:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.ENTROPY_HIGH_SECTION,
                    details={"section": name, "entropy": e, "raw_size": raw_size},
                ))

            # Very low entropy
            if raw_size >= MIN_SECTION_SIZE_FOR_LOW_ENTROPY and e <= LOW_ENTROPY_THRESHOLD:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.ENTROPY_VERY_LOW_SECTION,
                    details={"section": name, "entropy": e, "raw_size": raw_size},
                ))

    # ---------------------------------------------------------
    # 2) Overlay entropy
    # ---------------------------------------------------------
    overlay_info = analysis.get("overlay")
    if isinstance(overlay_info, dict):
        ov_entropy = overlay_info.get("entropy")
        ov_size = overlay_info.get("size")

        if isinstance(ov_entropy, (int, float)) and isinstance(ov_size, int):
            e = float(ov_entropy)
            if ov_size >= MIN_OVERLAY_SIZE_FOR_ENTROPY and e >= HIGH_ENTROPY_THRESHOLD:
                issues.append(StructuralIssue(
                    issue=ReasonCodes.ENTROPY_HIGH_OVERLAY,
                    details={"entropy": e, "size": ov_size},
                ))

    # ---------------------------------------------------------
    # 3) Region-specific entropy (optional)
    # ---------------------------------------------------------
    region_entropy = analysis.get("region_entropy") or {}

    region_map = {
        "resources": ReasonCodes.ENTROPY_HIGH_RESOURCES,
        "relocations": ReasonCodes.ENTROPY_HIGH_RELOCATIONS,
        "imports": ReasonCodes.ENTROPY_HIGH_IMPORTS,
        "tls": ReasonCodes.ENTROPY_HIGH_TLS,
        "certificate": ReasonCodes.ENTROPY_HIGH_CERTIFICATE,
    }

    for region, reason in region_map.items():
        info = region_entropy.get(region)
        if isinstance(info, dict):
            e = info.get("entropy")
            size = info.get("size")
            if isinstance(e, (int, float)) and isinstance(size, int):
                if size >= MIN_SECTION_SIZE_FOR_ENTROPY and e >= HIGH_ENTROPY_THRESHOLD:
                    issues.append(StructuralIssue(
                        issue=reason,
                        details={"entropy": float(e), "size": size},
                    ))

    # ---------------------------------------------------------
    # 4) Uniform entropy across sections
    # ---------------------------------------------------------
    if len(entropies) >= 2:
        mean = sum(entropies) / len(entropies)
        var = sum((e - mean) ** 2 for e in entropies) / len(entropies)
        stddev = var ** 0.5

        if mean >= HIGH_ENTROPY_THRESHOLD and stddev <= UNIFORM_STDDEV_THRESHOLD:
            issues.append(StructuralIssue(
                issue=ReasonCodes.ENTROPY_UNIFORM_ACROSS_SECTIONS,
                details={"mean_entropy": mean, "stddev_entropy": stddev, "count": len(entropies)},
            ))

    return issues
