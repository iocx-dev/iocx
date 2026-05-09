# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.engine import Engine


@pytest.fixture
def engine():
    return Engine()


def test_dedupe_case_sensitive_filepaths(engine):
    text = "C:\\Test C:\\Test c:\\test"
    result = engine.extract(text)
    # Case-sensitive dedupe → both preserved
    assert result["iocs"]["filepaths"] == ["C:\\Test", "c:\\test"]


def test_dedupe_case_sensitive_crypto(engine):
    text = (
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
        "1boatSLRHtKNngkdXEeobR76b53LETtpyT"
    )
    result = engine.extract(text)
    assert result["iocs"]["crypto.btc"] == ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"]


def test_dedupe_case_sensitive_base64(engine):
    text = "QUJDQUJDQUJD aGVsbG8gd29ybGQ="
    result = engine.extract(text)
    assert result["iocs"]["base64"] == ["QUJDQUJDQUJD", "aGVsbG8gd29ybGQ="]


def test_domains_lowercased_if_detector_emits_lowercase(engine):
    # Your engine does NOT lowercase domains — detectors decide.
    text = "Example.COM example.com"
    result = engine.extract(text)
    # If your detector lowercases, this will pass.
    # If not, update expected values accordingly.
    assert result["iocs"]["domains"] in (
        ["example.com"], # detector lowercases
        ["Example.COM", "example.com"] # detector preserves case
    )


def test_emails_lowercased_if_detector_emits_lowercase(engine):
    text = "Test@Example.COM test@example.com"
    result = engine.extract(text)
    # Same logic as domains — engine does not normalise.
    assert result["iocs"]["emails"] in (
        ["test@example.com"],
        ["Test@Example.COM", "test@example.com"],
    )


def test_hashes_lowercased_if_detector_emits_lowercase(engine):
    text = "AABBCCDDEEFF aabbccddeeff"
    result = engine.extract(text)
    assert result["iocs"]["hashes"] in (
        ["aabbccddeeff"],
        ["AABBCCDDEEFF", "aabbccddeeff"],
    )

# Normaliser should lowercase schema and host but preserve the rest
def test_urls_preserve_case(engine):
    text = "HTTP://Test.COM/Path"
    result = engine.extract(text)
    assert result["iocs"]["urls"] == ["http://test.com/Path"]


def test_no_empty_values(engine):
    text = " "
    results = engine.extract(text)

    assert "iocs" in results
    iocs = results["iocs"]

    for category, values in iocs.items():
        assert isinstance(values, list)
        assert all(v.strip() != "" for v in values)


def test_no_whitespace_padding(engine):
    text = " example.com "
    result = engine.extract(text)
    # Detector should emit clean values
    assert all(v == v.strip() for v in result["iocs"]["domains"])


def test_overlap_suppression(engine):
    text = "http://example.com example.com"
    result = engine.extract(text)

    # URL fully contains domain → domain suppressed
    assert result["iocs"]["urls"] == ["http://example.com"]
    assert result["iocs"]["domains"] == []


def test_order_preserved_after_dedupe(engine):
    text = "a.com b.com a.com"
    result = engine.extract(text)
    # First occurrence kept, order preserved
    assert result["iocs"]["domains"] == ["a.com", "b.com"]
