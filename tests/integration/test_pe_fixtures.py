import json
import subprocess
import pathlib
import pytest

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
BIN_DIR = FIXTURE_DIR / "bin"
MANIFEST_DIR = FIXTURE_DIR / "manifests"

def load_manifest(name: str):
    """Load the manifest JSON for a given fixture."""
    manifest_path = MANIFEST_DIR / f"{name}.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_fixture_test(name: str):
    """Run extraction against a fixture and assert expected IOCs."""
    manifest = load_manifest(name)
    exe_path = BIN_DIR / f"{name}.exe"

    result = subprocess.run(
        ["iocx", str(exe_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    found = json.loads(result.stdout)

    expected = set(manifest["expected_iocs"])

    flat = []
    for values in found["iocs"].values():
        flat.extend(values)

    # Normalise found IOCs:
    # - lowercase (for filepaths)
    # - strip " (decoded: ...)" for base64 entries
    normalised = set()

    for s in flat:
        s_str = str(s)

        # If it's a base64 entry like "XXX (decoded: YYY)", keep the raw XXX too
        if " (decoded:" in s_str:
            raw = s_str.split(" ", 1)[0]
            normalised.add(raw.lower())

        normalised.add(s_str.lower())

    # Also normalise expected to lowercase for comparison
    expected_normalised = {e.lower() for e in expected}

    missing = expected_normalised - normalised
    assert not missing, f"Missing IOCs in {name}: {missing}"


@pytest.mark.parametrize("fixture", [
    "pe_basic",
    "pe_utf16",
    "pe_rsrc",
    "pe_overlay",
    "pe_chaos",
    "pe_dense",
])

@pytest.mark.integration
def test_pe_fixtures(fixture):
    run_fixture_test(fixture)
