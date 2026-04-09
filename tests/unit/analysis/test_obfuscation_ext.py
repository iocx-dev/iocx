import pytest
from iocx.analysis.obfuscation import analyse_obfuscation

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
