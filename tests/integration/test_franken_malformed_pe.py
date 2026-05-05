import json
import subprocess
import pytest
from pathlib import Path

FIXTURE = Path("tests/contract/fixtures/layer3_adversarial/franken_malformed_pe.full.exe")
SNAPSHOT = Path("tests/contract/snapshots/layer3_adversarial/franken_malformed_pe.full.json")

@pytest.fixture(scope="module")
def franken_result():
    """Run IOCX on the franken malformed payload and return parsed JSON."""

    proc = subprocess.run(
        ["iocx", str(FIXTURE), "-a", "full"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)

@pytest.mark.integration
def test_franken_malformed_pe_snapshot(franken_result):
    """Franken must produce deterministic, stable output."""
    result = franken_result
    expected = json.loads(SNAPSHOT.read_text())

    assert result == expected

@pytest.mark.integration
def test_franken_expected_heuristics(franken_result):
    result = franken_result

    heur = {
        h["metadata"]["reason"]
        for h in result["analysis"]["heuristics"]
    }

    expected = {
        "entrypoint_out_of_bounds",
        "optional_header_inconsistent_size",
        "data_directory_out_of_range",
        "data_directory_zero_rva_nonzero_size",
        "section_raw_misaligned",
        "section_overlap",
        "section_raw_overlap"
    }

    print(heur)

    assert heur == expected

@pytest.mark.integration
def test_franken_no_iocs(franken_result):
    result = franken_result

    assert result["iocs"]["urls"] == []
    assert result["iocs"]["domains"] == []
    assert result["iocs"]["ips"] == []
    assert result["iocs"]["hashes"] == []
    assert result["iocs"]["emails"] == []
    assert result["iocs"]["filepaths"] == []
    assert result["iocs"]["base64"] == []
    assert result["iocs"]["crypto.btc"] == []
    assert result["iocs"]["crypto.eth"] == []

@pytest.mark.integration
def test_franken_section_names(franken_result):
    result = franken_result
    names = [s["name"] for s in result["analysis"]["sections"]]

    assert names == [".text", ".rdata", ".data", ".rsrc"]

@pytest.mark.integration
def test_franken_entrypoint(franken_result):
    result = franken_result
    assert result["metadata"]["header"]["entry_point"] == 12288

@pytest.mark.integration
def test_franken_image_base(franken_result):
    result = franken_result
    assert result["metadata"]["header"]["image_base"] == 5368709120
