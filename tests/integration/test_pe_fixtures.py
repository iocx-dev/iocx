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

    # found = extract(str(exe_path))
    result = subprocess.run(
        ["iocx", str(exe_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0

    found = json.loads(result.stdout)

    expected = set(manifest["expected_iocs"])
    found_set = set(found)

    # Assert all expected IOCs are present
    missing = expected - found_set
    assert not missing, f"Missing IOCs in {name}: {missing}"

@pytest.mark.parametrize("fixture", [
    "pe_basic",
    "pe_utf16",
    "pe_rsrc",
    "pe_overlay",
])

@pytest.mark.integration
def test_pe_fixtures(fixture):
    run_fixture_test(fixture)
