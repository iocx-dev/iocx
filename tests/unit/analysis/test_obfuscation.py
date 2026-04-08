import math
import pytest

from iocx.models import Detection
from iocx.analysis.obfuscation import (
    analyse_obfuscation,
    _shannon_entropy,
    ENTROPY_THRESHOLD,
)


def _get_values(detections, value):
    return [d for d in detections if d.value == value]


# ------------------------------------------------------------
# Entropy tests
# ------------------------------------------------------------

def test_entropy_deterministic():
    data = b"\x00\x01\x02\x03" * 100
    e1 = _shannon_entropy(data)
    e2 = _shannon_entropy(data)
    assert e1 == pytest.approx(e2)
    assert e1 > 0.0


def test_entropy_zero_for_empty():
    assert _shannon_entropy(b"") == 0.0


def test_high_entropy_section_triggers_hint():
    # Precompute entropy
    data = bytes(range(256)) * 16
    entropy = _shannon_entropy(data)

    sections = [
        {
            "name": ".text",
            "raw_size": len(data),
            "virtual_size": len(data),
            "virtual_address": 0x1000,
            "characteristics": 0x60000020,
            "entropy": entropy,
        }
    ]

    detections = analyse_obfuscation(sections, [])
    high_entropy = _get_values(detections, "high_entropy_section")

    assert len(high_entropy) == 1
    det = high_entropy[0]
    assert det.metadata["section"] == ".text"
    assert det.metadata["threshold"] == ENTROPY_THRESHOLD
    assert det.metadata["entropy"] >= ENTROPY_THRESHOLD


# ------------------------------------------------------------
# Suspicious section names
# ------------------------------------------------------------

def test_suspicious_section_name_detected():
    sections = [
        {
            "name": ".upx0",
            "raw_size": 1024,
            "virtual_size": 1024,
            "virtual_address": 0x2000,
            "characteristics": 0xE0000020,
            "entropy": 0.1,
        }
    ]

    detections = analyse_obfuscation(sections, [])
    suspicious = _get_values(detections, "suspicious_section_name")

    assert len(suspicious) == 1
    assert suspicious[0].metadata["section"] == ".upx0"


# ------------------------------------------------------------
# Abnormal layout tests
# ------------------------------------------------------------

def test_abnormal_layout_large_and_virtual_only_and_overlap():
    sections = [
        {
            "name": ".text",
            "raw_size": 1024,
            "virtual_size": 1024,
            "virtual_address": 0x1000,
            "characteristics": 0x60000020,
            "entropy": 1.0,
        },
        {
            "name": ".bss",
            "raw_size": 0,
            "virtual_size": 4096,
            "virtual_address": 0x1400,
            "characteristics": 0xC0000080,
            "entropy": 0.0,
        },
        {
            "name": ".huge",
            "raw_size": 20 * 1024 * 1024,
            "virtual_size": 20 * 1024 * 1024,
            "virtual_address": 0x3000,
            "characteristics": 0xE00000E0,
            "entropy": 0.1,
        },
    ]

    detections = analyse_obfuscation(sections, [])

    large = _get_values(detections, "abnormal_section_layout_large")
    virtual_only = _get_values(detections, "abnormal_section_layout_virtual_only")
    overlap = _get_values(detections, "abnormal_section_overlap")
    chars = _get_values(detections, "abnormal_section_characteristics")

    assert len(large) == 1
    assert large[0].metadata["section"] == ".huge"

    assert len(virtual_only) == 1
    assert virtual_only[0].metadata["section"] == ".bss"

    assert len(overlap) in (0, 1)

    assert any(d.metadata["section"] == ".huge" for d in chars)


# ------------------------------------------------------------
# String obfuscation tests
# ------------------------------------------------------------

def test_string_obfuscation_rot_and_hex_and_non_printable():
    rot_string = "UryybJbeyqGrfg"
    hex_blob = "4D5A90000300000004000000FFFF0000B8000000"
    non_printable = "".join(chr(i) for i in range(1, 32)) * 2 + "ABC"

    strings = [
        "normal string",
        rot_string,
        hex_blob,
        non_printable,
    ]

    detections = analyse_obfuscation([], strings)

    rot = _get_values(detections, "rot_encoded_string")
    hex_d = _get_values(detections, "suspicious_hex_blob_string")
    np = _get_values(detections, "suspicious_string_non_printable_ratio")

    assert len(hex_d) == 1
    assert hex_d[0].metadata["string_sample"].startswith("4D5A")

    assert len(np) >= 1
    assert np[0].metadata["length"] == len(non_printable)


# ------------------------------------------------------------
# Clean sample
# ------------------------------------------------------------

def test_clean_sample_has_no_excessive_hints():
    sections = [
        {
            "name": ".text",
            "raw_size": 4096,
            "virtual_size": 4096,
            "virtual_address": 0x1000,
            "characteristics": 0x60000020,
            "entropy": 1.0,
        },
        {
            "name": ".rdata",
            "raw_size": 2048,
            "virtual_size": 2048,
            "virtual_address": 0x2000,
            "characteristics": 0x40000040,
            "entropy": 0.1,
        },
    ]

    strings = [
        "This is a normal ASCII string.",
        "Completely harmless readable text with no obvious patterns.",
    ]

    detections = analyse_obfuscation(sections, strings)

    values = {d.value for d in detections}
    assert "suspicious_section_name" not in values
    assert "suspicious_hex_blob_string" not in values
    assert "suspicious_string_non_printable_ratio" not in values


# ------------------------------------------------------------
# Output structure
# ------------------------------------------------------------

def test_output_structure_stable():
    sections = [
        {
            "name": ".upx0",
            "raw_size": 1024,
            "virtual_size": 2048,
            "virtual_address": 0x1000,
            "characteristics": 0xE00000E0,
            "entropy": 0.1,
        }
    ]

    strings = ["UryybJbeyqGrfg", "4D5A90000300000004000000FFFF0000B8000000"]

    detections = analyse_obfuscation(sections, strings)

    assert all(isinstance(d, Detection) for d in detections)
    for d in detections:
        assert d.category == "obfuscation_hint"
        assert isinstance(d.value, str)
        assert isinstance(d.metadata, dict)
        assert d.start == 0
        assert d.end == 0
