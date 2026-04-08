import pytest
from iocx.analysis.obfuscation import analyse_obfuscation
from tests.unit.analysis.fixtures import make_sections, make_strings


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
