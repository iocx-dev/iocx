# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.engine import Engine


@pytest.fixture
def engine():
    return Engine()


def test_overlap_ip_inside_url(engine):
    text = "https://156.65.42.8/access.php 192.65.43.8"
    result = engine.extract(text)

    assert "https://156.65.42.8/access.php" in result["iocs"]["urls"]
    assert "192.65.43.8" in result["iocs"]["ips"]


def test_overlap_domain_inside_url(engine):
    text = "http://example.com example.com"
    result = engine.extract(text)

    assert result["iocs"]["urls"] == ["http://example.com"]
    assert result["iocs"]["domains"] == []


def test_partial_overlap_no_containment(engine):
    text = "http://example.com/path?x=1"
    result = engine.extract(text)

    assert result["iocs"]["urls"]


def test_equal_range_different_categories(engine):
    text = "example.com"
    result = engine.extract(text)

    assert "example.com" in "".join(" ".join(v) for v in result["iocs"].values())


def test_email_contains_domain(engine):
    text = "user@example.com example.com"
    result = engine.extract(text)

    emails = result["iocs"].get("emails", [])
    domains = result["iocs"].get("domains", [])

    assert "user@example.com" in emails
    assert "example.com" in domains


def test_order_preserved_after_overlap_and_dedupe(engine):
    text = "http://a.com http://b.com a.com b.com"
    result = engine.extract(text)

    assert result["iocs"]["urls"] == ["http://a.com", "http://b.com"]


def test_equal_range_suppression(engine):
    # Simulate two detectors emitting identical spans
    text = "example.com"
    # Domain detector and URL detector may both match the same span
    result = engine.extract(text)

    # Engine keeps only the first match in sorted order
    # Assert that only one category contains the value
    occurrences = sum(
        1 for cat, vals in result["iocs"].items() if "example.com" in vals
    )
    assert occurrences == 1


def test_partial_overlap_greedy_selection(engine):
    # Force two overlapping but not contained matches
    text = "abc@example.com/path"
    result = engine.extract(text)

    # At least one IOC must survive; engine should not suppress both
    total = sum(len(v) for v in result["iocs"].values())
    assert total >= 1


def test_filepath_inside_url(engine):
    text = "http://example.com/C:/Windows/System32/calc.exe C:\\Windows\\System32\\calc.exe"
    result = engine.extract(text)

    # Standalone filepath must survive
    assert r"C:\Windows\System32\calc.exe" in result["iocs"]["filepaths"]

    # Only one instance should appear (inner one suppressed)
    assert result["iocs"]["filepaths"].count(r"C:\Windows\System32\calc.exe") == 1
