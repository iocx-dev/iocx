from iocx.validators.normalise import normalise_iocs


def test_normalise_iocs_full_coverage():
    raw = {
        "domains": [" Example.COM ", "", None],
        "emails": [" USER@Example.COM ", "", None],
        "urls": [" HTTP://Test.COM/Path ", "", None],
        "ips": [" 8.8.8.8 ", ""], # should NOT lowercase
        "hashes": [" ABCDEF123456 ", "", None], # should NOT lowercase
    }

    result = normalise_iocs(raw)

    # domains → stripped + lowercased, empties removed
    assert result["domains"] == ["example.com"]

    # emails → stripped + lowercased, empties removed
    assert result["emails"] == ["user@example.com"]

    # urls → stripped + lowercased
    assert result["urls"] == ["http://test.com/path"]

    # ips → stripped only, case preserved (not that it matters for digits)
    assert result["ips"] == ["8.8.8.8"]

    # hashes → stripped only, case preserved
    assert result["hashes"] == ["ABCDEF123456"]
