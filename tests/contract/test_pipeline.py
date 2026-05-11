# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Contract‑Safe Snapshot Tests

These tests enforce the IOCX behavioural contract:
Same file → same output → every time.

All tests in this file are marked with @pytest.mark.contract.
"""
import json
import pathlib
import pytest
from iocx.engine import Engine

@pytest.fixture
def engine():
    return Engine()


FIXTURES_DIR = pathlib.Path("tests/contract/fixtures")
SNAPSHOTS_DIR = pathlib.Path("tests/contract/snapshots")


def load_snapshot(snapshot_path):
    with open(snapshot_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_snapshot(snapshot_path, data):
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def discover_fixtures():
    """Yield (fixture_path, snapshot_path, level) pairs for all layers."""
    for fixture in FIXTURES_DIR.rglob("*"):
        if fixture.is_file() and fixture.suffix.lower() in ('.exe', '.bin'):
            rel = fixture.relative_to(FIXTURES_DIR)
            snapshot = SNAPSHOTS_DIR / rel.with_suffix(".json")

            name = fixture.stem.lower()
            if name.endswith(".full"):
                level = "full"
            elif name.endswith(".deep"):
                level = "deep"
            elif name.endswith(".basic"):
                level = "basic"
            else:
                level = "None"

            yield fixture, snapshot, level

@pytest.mark.contract
@pytest.mark.parametrize("fixture_path,snapshot_path,level", discover_fixtures())
def test_contract_safe_pipeline(engine, fixture_path, snapshot_path, level):

    print(f"\n> {fixture_path}")

    engine._analysis_level = level
    output = engine.extract(fixture_path)

    # Normalise file path to string for deterministic snapshot comparison
    if isinstance(output.get("file"), pathlib.Path):
        output["file"] = str(output["file"])

    if not snapshot_path.exists():
        # First run: create snapshot
        save_snapshot(snapshot_path, output)
        pytest.fail(f"Snapshot created for {fixture_path}, please review and re-run.")

    expected = load_snapshot(snapshot_path)

    assert output == expected, (
        f"Contract violation for {fixture_path}.\n"
        f"Snapshot: {snapshot_path}\n"
        f"Output differs from expected."
    )
