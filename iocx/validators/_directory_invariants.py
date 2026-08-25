# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Shared, side-effect-free helpers for the v0.7.6 directory-invariant
validators (relocations, certificates, debug, TLS).

These functions encode the "does this RVA/region map to loaded content"
policy in one place so every directory validator applies it identically
and deterministically.

Expected analysis shape (all optional; checks degrade gracefully):

    analysis["size_of_image"]  -> int
    analysis["sections"]       -> List[{"rva": int, "virtual_size": int}]

If `sections` is absent we fall back to a SizeOfImage bound check only;
if `size_of_image` is also absent we skip the check entirely rather than
guess (an upstream gap is not a directory defect).
"""

from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "region_within_image",
    "rva_in_any_section",
    "region_in_any_section",
]


def region_within_image(
    rva: Optional[int],
    size: Optional[int],
    size_of_image: Optional[int],
) -> Optional[bool]:
    """
    True if [rva, rva+size) lies within SizeOfImage.

    Returns None when the check cannot be performed (missing inputs) so
    callers can distinguish "unknown" from "out of bounds".
    """
    if rva is None or size_of_image is None:
        return None
    span = size or 0
    if rva < 0 or span < 0:
        return False
    return (rva + span) <= size_of_image


def _sections(analysis: Dict[str, Any]) -> List[Tuple[int, int]]:
    """Extract [(rva, virtual_size), ...] from analysis, tolerating keys."""
    out: List[Tuple[int, int]] = []
    for sec in analysis.get("sections", []) or []:
        rva = sec.get("rva", sec.get("virtual_address"))
        vsize = sec.get("virtual_size", sec.get("size"))
        if rva is None or vsize is None:
            continue
        try:
            out.append((int(rva), int(vsize)))
        except (ValueError, TypeError):
            continue
    return out


def rva_in_any_section(
    rva: Optional[int],
    analysis: Dict[str, Any],
    size_of_image=None,
) -> Optional[bool]:
    """
    True if `rva` falls inside any section's virtual extent.

    Falls back to a SizeOfImage bound check when section data is absent.
    Returns None when neither is available.
    """
    if rva is None:
        return None

    sections = _sections(analysis)
    if sections:
        for base, vsize in sections:
            if base <= rva < base + max(vsize, 0):
                return True
        return False

    return region_within_image(rva, 0, size_of_image)


def region_in_any_section(
    rva: Optional[int],
    size: Optional[int],
    analysis: Dict[str, Any],
    size_of_image=None,
) -> Optional[bool]:
    """
    True if the whole region [rva, rva+size) fits inside a single section.

    Falls back to a SizeOfImage bound check when section data is absent.
    Returns None when neither is available.
    """
    if rva is None:
        return None
    span = size or 0

    sections = _sections(analysis)
    if sections:
        for base, vsize in sections:
            end = base + max(vsize, 0)
            if base <= rva and (rva + span) <= end:
                return True
        return False

    return region_within_image(rva, span, size_of_image)
