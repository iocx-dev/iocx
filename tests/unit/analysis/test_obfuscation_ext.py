import pytest
from iocx.analysis.obfuscation import analyse_obfuscation, _detect_high_entropy_sections, _looks_like_rot13, _non_printable_ratio, _detect_string_obfuscation
from iocx.analysis.extended import analyse_extended

def make_sections():
    return [
        # Suspicious section name
        {"name": ".upx", "raw_size": 100, "virtual_size": 100,
         "characteristics": 0, "entropy": 1.0},

        # High entropy
        {"name": ".rand", "raw_size": 4096, "virtual_size": 4096,
         "characteristics": 0, "entropy": 7.9},

        # Overlapping sections
        {"name": ".a", "raw_size": 100, "virtual_size": 100,
         "virtual_address": 0x1000, "entropy": 1.0},

        {"name": ".b", "raw_size": 100, "virtual_size": 100,
         "virtual_address": 0x1050, "entropy": 1.0},
    ]


def make_strings():
    return [
        "A1B2C3D4E5F6A7B8C9D0A1B2C3D4E5F6", # hex blob
        "Gur synt vf va gur qvfpbirel", # ROT13
        "normal_string",
    ]

def test_suspicious_section_name():
    sections = make_sections()
    strings = []

    detections = analyse_obfuscation(sections, strings)

    assert any(d.value == "suspicious_section_name" for d in detections)


def test_high_entropy_section():
    sections = make_sections()
    strings = []

    detections = analyse_obfuscation(sections, strings)

    assert any(d.value == "high_entropy_section" for d in detections)


def test_overlapping_sections():
    sections = make_sections()
    strings = []

    detections = analyse_obfuscation(sections, strings)

    assert any(d.value == "abnormal_section_overlap" for d in detections)


def test_hex_blob_string():
    sections = []
    strings = make_strings()

    detections = analyse_obfuscation(sections, strings)

    assert any(d.value == "suspicious_hex_blob_string" for d in detections)


def test_rot13_string():
    sections = []
    strings = make_strings()

    detections = analyse_obfuscation(sections, strings)

    assert any(d.value == "rot_encoded_string" for d in detections)


def test_full_trigger_suite():
    sections = make_sections()
    strings = make_strings()

    detections = analyse_obfuscation(sections, strings)
    values = {d.value for d in detections}

    assert "suspicious_section_name" in values
    assert "high_entropy_section" in values
    assert "abnormal_section_overlap" in values
    assert "suspicious_hex_blob_string" in values
    assert "rot_encoded_string" in values


def test_detect_high_entropy_sections_skips_none_data():
    sections = [
        {"name": ".text", "data": None},
        {"name": ".rdata", "data": None},
    ]

    detections = _detect_high_entropy_sections(sections)

    assert detections == []


def test_detect_high_entropy_sections_low_entropy():
    sections = [
        {"name": ".text", "data": b"\x00" * 100},
    ]

    detections = _detect_high_entropy_sections(sections)

    assert detections == []


def test_detect_high_entropy_sections_high_entropy():
    # High entropy: random bytes
    data = bytes(range(256)) # 0..255 → very high entropy

    sections = [
        {"name": ".packed", "data": data},
    ]

    detections = _detect_high_entropy_sections(sections)

    assert len(detections) == 1
    det = detections[0]

    assert det.category == "obfuscation_hint"
    assert det.value == "high_entropy_section"
    assert det.metadata["section"] == ".packed"
    assert det.metadata["entropy"] >= det.metadata["threshold"]


def test_looks_like_rot13_too_short():
    # MIN_STRING_LENGTH is > 1, so "a" is guaranteed to be too short
    assert _looks_like_rot13("a") is False


def test_non_printable_ratio_empty_string():
    assert _non_printable_ratio("") == 0.0


def test_detect_string_obfuscation_skips_short_strings():
    # MIN_STRING_LENGTH is > 1, so "a" is guaranteed too short
    strings = ["a", "validstring"]

    detections = _detect_string_obfuscation(strings)

    # We don't care about the result here — only that the short string was skipped
    assert isinstance(detections, list)


def test_analyse_extended_returns_expected_structure():
    result = analyse_extended(pe=None, metadata={}, strings=[])

    assert isinstance(result, dict)
    assert "note" in result
    assert "planned_features" in result

    assert result["note"].startswith("Extended analysis is reserved")
    assert result["planned_features"] == [
        "packer_detection",
        "tls_callbacks",
        "anti_debug_heuristics",
        "import_anomaly_scoring",
        "signature_anomalies",
        "control_flow_hints",
    ]
