# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import json
import pytest
from pathlib import Path
from iocx.engine import Engine

@pytest.fixture
def engine():
    return Engine()

# --- snapshot loader ---------------------------------------------------------

def load_snapshot(name: str):
    path = Path("tests/contract/snapshots") / f"{name}.json"
    return json.loads(path.read_text())


# --- normalisers for each analysis level ------------------------------------

def normalise_core(output):
    # Top-level
    output["file"] = "pe_chaos.exe" # snapshot uses a placeholder
    output["type"] = "PE"

    # IOC categories always exist but content varies
    for key in output["iocs"]:
        output["iocs"][key] = []

    # Metadata structure
    md = output["metadata"]

    md["imports"] = []
    md["sections"] = []
    md["resources"] = []
    md["resource_strings"] = []
    md["import_details"] = []
    md["delayed_imports"] = []
    md["bound_imports"] = []
    md["exports"] = []

    # TLS
    md["tls"] = {
        "start_address": None,
        "end_address": None,
        "callbacks": None,
    }

    # Header (blank all fields)
    md["header"] = {
        "entry_point": None,
        "image_base": None,
        "subsystem": None,
        "timestamp": None,
        "machine": None,
        "characteristics": None,
    }

    # Optional header (blank all fields)
    md["optional_header"] = {
        "section_alignment": None,
        "file_alignment": None,
        "size_of_image": None,
        "size_of_headers": None,
        "linker_version": None,
        "os_version": None,
        "subsystem_version": None,
    }

    md["rich_header"] = None
    md["signatures"] = []
    md["has_signature"] = False

    # Remove analysis for core mode
    output.pop("analysis", None)

    return output


def normalise_basic(output):
    output = normalise_core(output)
    output["analysis"] = {"sections": []}
    return output


def normalise_deep(output):
    output = normalise_core(output)
    output["analysis"] = {
        "sections": [],
        "obfuscation": []
    }
    return output


def normalise_full(output):
    output = normalise_core(output)
    output["analysis"] = {
        "sections": [],
        "obfuscation": [],
        "extended": [],
        "heuristics": [],
    }
    return output


def normalise_enrich(output):
    output = normalise_core(output)
    output["enrichment"] = {}
    return output


# --- parametrised test -------------------------------------------------------

@pytest.mark.parametrize(
    "mode,normaliser,snapshot",
    [
        ("None", normalise_core, "core"),
        ("basic", normalise_basic, "basic"),
        ("deep", normalise_deep, "deep"),
        ("full", normalise_full, "full"),
    ]
)
@pytest.mark.contract
def test_pipeline_snapshots(engine, mode, normaliser, snapshot):
    # Set the engine’s analysis level exactly as the CLI would
    engine.analysis_level = mode

    # Run the pipeline using the engine’s configured mode
    raw = engine.extract("tests/integration/fixtures/bin/pe_chaos.exe")

    # Normalise volatile fields and reduce to structural form
    output = normaliser(raw)

    # Load the minimal structural snapshot
    expected = load_snapshot(snapshot)

    # Structural contract enforcement
    assert output == expected

@pytest.mark.parametrize(
    "normaliser,snapshot",
    [
        (normalise_enrich, "enrich"),
    ]
)
@pytest.mark.contract
def test_pipeline_enrichment_snapshot(engine, normaliser, snapshot):
    raw = engine.extract("tests/integration/fixtures/bin/pe_chaos.exe")

    ctx = engine.plugin_context

    # enrichment output is a CLI decision so replicate that behaviour
    raw["enrichment"] = ctx.metadata

    # Normalise volatile fields and reduce to structural form
    output = normaliser(raw)

    # Load the minimal structural snapshot
    expected = load_snapshot(snapshot)

    # Structural contract enforcement
    assert output == expected
