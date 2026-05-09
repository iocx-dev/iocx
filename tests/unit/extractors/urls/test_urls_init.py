# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import iocx.detectors.extractors.urls as urls_extract


def test_extract_strict_url_continue(monkeypatch):
    # Patch the local imported names inside the extract module
    monkeypatch.setattr(urls_extract, "extract_strict_urls",
                        lambda text: [("bad://url", 0, 10)])
    monkeypatch.setattr(urls_extract, "extract_bare_domains",
                        lambda text: [])
    monkeypatch.setattr(urls_extract, "normalise_url",
                        lambda value: None)

    result = urls_extract.extract("anything")

    assert result["urls"] == []
    assert result["domains"] == []


def test_extract_bare_domain_continue(monkeypatch):
    monkeypatch.setattr(urls_extract, "extract_strict_urls",
                        lambda text: [])
    monkeypatch.setattr(urls_extract, "extract_bare_domains",
                        lambda text: [("example.com", 5, 17)])
    monkeypatch.setattr(urls_extract, "normalise_url",
                        lambda value: None)

    result = urls_extract.extract("anything")

    assert result["urls"] == []
    assert result["domains"] == []
