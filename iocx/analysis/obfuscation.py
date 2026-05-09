# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import math
import string
from typing import Dict, List, Any

from iocx.models import Detection


SUSPICIOUS_SECTION_NAMES = {
    ".upx",
    ".upx0",
    ".upx1",
    ".aspack",
    ".mpress",
    ".petite",
    ".themida",
    ".packed",
}

ENTROPY_THRESHOLD = 7.2
LARGE_SECTION_SIZE = 10 * 1024 * 1024 # 10 MB, heuristic
MIN_STRING_LENGTH = 8
MIN_OBFUSCATED_STRING_LENGTH = 16
NON_PRINTABLE_RATIO_THRESHOLD = 0.5
HEX_BLOB_MIN_LENGTH = 16


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _is_hex_blob(s: str) -> bool:
    if len(s) < HEX_BLOB_MIN_LENGTH:
        return False
    hex_chars = set(string.hexdigits)
    return all(ch in hex_chars for ch in s)


def _rot13(s: str) -> str:
    def _rot_char(c: str) -> str:
        if "a" <= c <= "z":
            return chr((ord(c) - ord("a") + 13) % 26 + ord("a"))
        if "A" <= c <= "Z":
            return chr((ord(c) - ord("A") + 13) % 26 + ord("A"))
        return c

    return "".join(_rot_char(c) for c in s)


def _looks_like_rot13(s: str) -> bool:
    if len(s) < MIN_STRING_LENGTH:
        return False

    decoded = _rot13(s)
    printable = sum(ch in string.printable for ch in decoded)
    if printable / max(1, len(decoded)) < 0.8:
        return False

    letters = sum(ch.isalpha() for ch in decoded)
    return letters / max(1, len(decoded)) > 0.5


def _non_printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(ch in string.printable for ch in s)
    return 1.0 - (printable / len(s))


def _detect_suspicious_section_names(sections: List[Dict[str, Any]]) -> List[Detection]:
    detections: List[Detection] = []
    for sec in sections:
        name = (sec.get("name") or "").lower()
        if name in SUSPICIOUS_SECTION_NAMES:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="suspicious_section_name",
                    metadata={"section": sec.get("name")},
                    start=0,
                    end=0,
                )
            )
    return detections


def _detect_high_entropy_sections(sections: List[Dict[str, Any]]) -> List[Detection]:
    detections: List[Detection] = []
    for sec in sections:
        name = sec.get("name")
        data = sec.get("data") # expected to be bytes if present
        if data is None:
            continue

        entropy = _shannon_entropy(data)
        if entropy >= ENTROPY_THRESHOLD:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="high_entropy_section",
                    metadata={
                        "section": name,
                        "entropy": entropy,
                        "threshold": ENTROPY_THRESHOLD,
                    },
                    start=0,
                    end=0,
                )
            )
    return detections


def _detect_abnormal_layout(sections: List[Dict[str, Any]]) -> List[Detection]:
    detections: List[Detection] = []

    # Extremely large sections, zero raw / non-zero virtual, unusual flags
    for sec in sections:
        name = sec.get("name")
        raw_size = int(sec.get("raw_size") or 0)
        virtual_size = int(sec.get("virtual_size") or 0)
        characteristics = sec.get("characteristics")

        if raw_size >= LARGE_SECTION_SIZE:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="abnormal_section_layout_large",
                    metadata={
                        "section": name,
                        "raw_size": raw_size,
                        "threshold": LARGE_SECTION_SIZE,
                    },
                    start=0,
                    end=0,
                )
            )

        if raw_size == 0 and virtual_size > 0:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="abnormal_section_layout_virtual_only",
                    metadata={
                        "section": name,
                        "raw_size": raw_size,
                        "virtual_size": virtual_size,
                    },
                    start=0,
                    end=0,
                )
            )

        if characteristics is not None and isinstance(characteristics, int):
            # Very simple heuristic: unusual combination of flags
            # e.g. both executable and writable
            IMAGE_SCN_MEM_EXECUTE = 0x20000000
            IMAGE_SCN_MEM_WRITE = 0x80000000
            if (characteristics & IMAGE_SCN_MEM_EXECUTE) and (
                characteristics & IMAGE_SCN_MEM_WRITE
            ):
                detections.append(
                    Detection(
                        category="obfuscation_hint",
                        value="abnormal_section_characteristics",
                        metadata={
                            "section": name,
                            "characteristics": characteristics,
                        },
                        start=0,
                        end=0,
                    )
                )

    # Overlapping sections (by virtual address range)
    ranges = []
    for sec in sections:
        va = sec.get("virtual_address")
        vs = sec.get("virtual_size")
        if va is None or vs is None:
            continue
        start = int(va)
        end = start + int(vs)
        ranges.append((start, end, sec.get("name")))

    ranges.sort(key=lambda x: x[0])
    for i in range(1, len(ranges)):
        prev_start, prev_end, prev_name = ranges[i - 1]
        cur_start, cur_end, cur_name = ranges[i]
        if cur_start < prev_end:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="abnormal_section_overlap",
                    metadata={
                        "section_a": prev_name,
                        "section_b": cur_name,
                        "range_a": [prev_start, prev_end],
                        "range_b": [cur_start, cur_end],
                    },
                    start=0,
                    end=0,
                )
            )

    return detections


def _detect_string_obfuscation(strings: List[str]) -> List[Detection]:
    detections: List[Detection] = []

    for s in strings:
        if len(s) < MIN_STRING_LENGTH:
            continue

        # High ratio of non-printable characters
        ratio = _non_printable_ratio(s)
        if ratio >= NON_PRINTABLE_RATIO_THRESHOLD and len(s) >= MIN_OBFUSCATED_STRING_LENGTH:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="suspicious_string_non_printable_ratio",
                    metadata={
                        "string_sample": s[:64],
                        "length": len(s),
                        "non_printable_ratio": ratio,
                    },
                    start=0,
                    end=0,
                )
            )

        # Hex blob (often used for encoded payloads / XOR data)
        if _is_hex_blob(s):
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="suspicious_hex_blob_string",
                    metadata={
                        "string_sample": s[:64],
                        "length": len(s),
                    },
                    start=0,
                    end=0,
                )
            )

        # ROT-encoded ASCII ranges
        if _looks_like_rot13(s):
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="rot_encoded_string",
                    metadata={
                        "string_sample": s[:64],
                        "length": len(s),
                    },
                    start=0,
                    end=0,
                )
            )

    return detections


def analyse_obfuscation(
    sections: List[Dict[str, Any]],
    strings: List[str]
) -> List[Dict[str, Any]]:
    """
    Analyse PE section structure + strings for static obfuscation / packing hints.

    Args:
        sections: structured section analysis from analyse_pe_sections()
        strings: extracted ASCII/Unicode strings

    Returns:
        List of obfuscation_hint detections.
    """

    # Ensure sections is always a list
    sections = sections or []

    detections: List[Detection] = []

    # Section-based heuristics
    detections.extend(_detect_suspicious_section_names(sections))
    detections.extend(_detect_abnormal_layout(sections))

    # High-entropy detection uses the precomputed entropy
    for sec in sections:
        entropy = sec.get("entropy")
        if entropy is not None and entropy >= ENTROPY_THRESHOLD:
            detections.append(
                Detection(
                    category="obfuscation_hint",
                    value="high_entropy_section",
                    metadata={
                        "section": sec.get("name"),
                        "entropy": entropy,
                        "threshold": ENTROPY_THRESHOLD,
                    },
                    start=0,
                    end=0,
                )
            )

    # String-based heuristics
    detections.extend(_detect_string_obfuscation(strings))

    return detections
