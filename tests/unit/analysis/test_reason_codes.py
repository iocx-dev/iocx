# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Regression tests for the heuristic reason-code contract.

BACKGROUND
----------
`_det()` builds its metadata as ``{"reason": reason, **(metadata or {})}``, so a
payload key literally named ``reason`` silently OVERWRITES the parent reason
code. Because ``_analyse_structural`` forwards each validator's ``details``
verbatim, any validator emitting ``details={"reason": ...}`` lost its parent
code in the output.

The bug was invisible for a long time: the clobbered output still *looked*
structured (a plausible string in a ``reason`` field), and
``analysis["structural"]`` is never copied into the result, so no unclobbered
view existed to compare against. Eleven documented reason codes had never once
appeared in output.

These tests lock the contract at both ends:

  * SOURCE  - no validator may put a top-level ``reason`` key in ``details``.
  * OUTPUT  - every ``pe_structure_anomaly`` reason must be a real ReasonCode.

Either test alone would have caught the original defect.

DESIGN NOTE
-----------
The membership assertion is deliberately scoped to ``pe_structure_anomaly``
detections. The behavioural heuristics (anti-debug, import anomalies) use their
own vocabulary - ``anti_debug_api_import``, ``rwx_section``,
``large_import_table`` etc. - which is intentionally NOT part of ReasonCodes.
Those are pinned by an explicit allowlist instead, so adding a new behavioural
reason is a conscious act rather than an accident.
"""

import pytest

from iocx.reason_codes import ReasonCodes
from iocx.analysis.heuristics import analyse_pe_heuristics


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _reason_code_values() -> set:
    """Every string value declared on ReasonCodes."""
    return {
        v for k, v in vars(ReasonCodes).items()
        if not k.startswith("_") and isinstance(v, str)
    }


def _as_dicts(detections):
    """Normalise Detection objects (or dicts) to plain dicts."""
    out = []
    for d in detections:
        if isinstance(d, dict):
            out.append(d)
        else:
            out.append({
                "value": d.value,
                "category": d.category,
                "metadata": d.metadata,
            })
    return out


# Behavioural heuristic reasons that are intentionally NOT ReasonCodes members.
# Adding to this set should be a deliberate decision, not a silent drift.
BEHAVIOURAL_REASONS = {
    "anti_debug_api_import",
    "timing_api_import",
    "rwx_section",
    "large_import_table",
    "high_ordinal_import_ratio",
    "uncommon_dll_for_gui_subsystem",
}


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def structural_payload():
    """
    One issue per validator that historically carried a colliding ``reason``
    key, plus controls that never did. Mirrors the real
    ``analysis["structural"]`` shape: {category: [ {issue, details}, ... ]}.
    """
    return {
        "load_config_directory": [
            {"issue": ReasonCodes.LOAD_CONFIG_SEH_INVALID,
             "details": {"seh_table_rva": 0, "seh_count": 4,
                         "sub_reason": "missing_table_rva"}},
            {"issue": ReasonCodes.LOAD_CONFIG_COOKIE_INVALID,
             "details": {"cookie_rva": 0x3500, "section": ".rdata",
                         "sub_reason": "non_writable_section"}},
            # control: never had a colliding key
            {"issue": ReasonCodes.LOAD_CONFIG_COOKIE_IN_OVERLAY,
             "details": {"cookie_rva": 0x3500, "cookie_raw": 0xB00,
                         "overlay_offset": 0x694}},
        ],
        "tls": [
            {"issue": ReasonCodes.TLS_DIRECTORY_TRUNCATED,
             "details": {"sub_reason": "header_decode", "errors": ["x"]}},
            {"issue": ReasonCodes.TLS_CALLBACK_RVA_INVALID,
             "details": {"callback_va": 0x401000,
                         "sub_reason": "below_image_base",
                         "invalid_callback_count": 1}},
        ],
        "sections": [
            {"issue": ReasonCodes.SECTION_FLAGS_INCONSISTENT,
             "details": {"section": ".text",
                         "sub_reason": "code_without_read"}},
            {"issue": ReasonCodes.SECTION_RWX,
             "details": {"section": ".text", "characteristics": 0xE0000020}},
        ],
        "entrypoint": [
            {"issue": ReasonCodes.ENTRYPOINT_IN_TRUNCATED_REGION,
             "details": {"entry_point": 0x1000, "section": ".text",
                         "sub_reason": "zero_length_section"}},
        ],
        "signature": [
            {"issue": ReasonCodes.CERTIFICATE_TABLE_MALFORMED,
             "details": {"sub_reason": "truncation", "region": "cert_blob"}},
        ],
        "version_info": [
            {"issue": ReasonCodes.RESOURCE_VERSIONINFO_INVALID_HEADER,
             "details": {"sub_reason": "szkey_mismatch"}},
        ],
        "exception_table": [
            # uses "table", never collided - must be untouched
            {"issue": ReasonCodes.EXCEPTION_TABLE_TRUNCATED,
             "details": {"table": "exception_entry_truncated"}},
        ],
    }


@pytest.fixture
def legacy_structural_payload():
    """
    An UNMIGRATED validator payload that still uses the reserved ``reason``
    key.

    This is the adversarial case: it proves the emission layer defends itself
    rather than relying on every validator having been migrated. Without it the
    output tests only assert the already-fixed state and would pass even
    against the original clobbering code.
    """
    return {
        "load_config_directory": [
            {"issue": ReasonCodes.LOAD_CONFIG_SEH_INVALID,
             "details": {"seh_table_rva": 0, "seh_count": 4,
                         "reason": "missing_table_rva"}},   # legacy key
        ],
    }


@pytest.fixture
def analysis(structural_payload):
    return {
        "sections": [],
        "extended": [],
        "obfuscation": [],
        "structural": structural_payload,
    }


# ==========================================================================
# OUTPUT CONTRACT
# ==========================================================================

def test_structural_reasons_are_declared_reason_codes(analysis):
    """
    THE regression test. Every ``pe_structure_anomaly`` reason must be a
    declared ReasonCode.

    Under the clobber bug this fails loudly: the emitted reasons were payload
    strings such as ``missing_table_rva`` and ``below_image_base``, which are
    sub-reasons and are not ReasonCodes members.
    """
    valid = _reason_code_values()

    offenders = []
    for det in _as_dicts(analyse_pe_heuristics({}, analysis)):
        if det["value"] != "pe_structure_anomaly":
            continue
        reason = det["metadata"].get("reason")
        if reason not in valid:
            offenders.append(reason)

    assert not offenders, (
        "pe_structure_anomaly emitted reason(s) that are not declared in "
        f"ReasonCodes: {sorted(set(offenders))}. This usually means a "
        "validator put a top-level 'reason' key in its details payload, which "
        "_det() merges OVER the parent reason code. Use 'sub_reason' instead."
    )


def test_every_structural_parent_code_survives(analysis, structural_payload):
    """
    Stronger form: the emitted reason must equal the *specific* parent code the
    validator raised, one-for-one and in order.
    """
    expected = [
        issue["issue"]
        for issues in structural_payload.values()
        for issue in issues
    ]
    emitted = [
        d["metadata"]["reason"]
        for d in _as_dicts(analyse_pe_heuristics({}, analysis))
        if d["value"] == "pe_structure_anomaly"
    ]

    assert emitted == expected, (
        "Structural parent codes were altered in transit.\n"
        f"  expected: {expected}\n"
        f"  emitted : {emitted}"
    )


def test_sub_reason_is_preserved_alongside_parent(analysis):
    """
    The parent must not win by *destroying* the sub-reason. Both survive.

    This guards against the naive 'fix' of reordering the merge so the parent
    overwrites the payload - that trades one information loss for another.
    """
    by_reason = {
        d["metadata"]["reason"]: d["metadata"]
        for d in _as_dicts(analyse_pe_heuristics({}, analysis))
        if d["value"] == "pe_structure_anomaly"
    }

    md = by_reason[ReasonCodes.LOAD_CONFIG_SEH_INVALID]
    assert md.get("sub_reason") == "missing_table_rva"
    # payload fields must survive intact too
    assert md.get("seh_table_rva") == 0
    assert md.get("seh_count") == 4


def test_no_sub_reason_key_invented_when_none_existed(analysis):
    """
    Issues whose details never carried a colliding key must be untouched - no
    spurious ``sub_reason`` added.
    """
    by_reason = {
        d["metadata"]["reason"]: d["metadata"]
        for d in _as_dicts(analyse_pe_heuristics({}, analysis))
        if d["value"] == "pe_structure_anomaly"
    }

    assert "sub_reason" not in by_reason[ReasonCodes.LOAD_CONFIG_COOKIE_IN_OVERLAY]
    assert "sub_reason" not in by_reason[ReasonCodes.SECTION_RWX]
    # 'table' is a distinct key and must be passed through unchanged
    assert by_reason[ReasonCodes.EXCEPTION_TABLE_TRUNCATED]["table"] == \
        "exception_entry_truncated"


def test_legacy_reason_key_cannot_clobber_parent(legacy_structural_payload):
    """
    THE bug, reproduced exactly.

    A validator that has not been migrated still emits ``details={"reason":
    ...}``. The pipeline must survive that: the parent code wins and the legacy
    value is preserved under ``sub_reason``.

    Against the original code this fails with
    ``reason == "missing_table_rva"``.
    """
    analysis = {"sections": [], "extended": [], "obfuscation": [],
                "structural": legacy_structural_payload}

    dets = [d for d in _as_dicts(analyse_pe_heuristics({}, analysis))
            if d["value"] == "pe_structure_anomaly"]
    assert len(dets) == 1
    md = dets[0]["metadata"]

    assert md["reason"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID, (
        "A legacy 'reason' detail key overwrote the parent reason code. The "
        "emission layer must re-key it to 'sub_reason' before merging."
    )
    assert md.get("sub_reason") == "missing_table_rva", (
        "The parent code was preserved by DESTROYING the sub-reason. Both must "
        "survive - re-key the collision, do not simply reorder the merge."
    )
    assert md["seh_count"] == 4  # payload intact


def test_behavioural_reasons_match_allowlist():
    """
    Behavioural heuristics use a vocabulary outside ReasonCodes. Pin it, so a
    new reason string is a deliberate change rather than silent drift.
    """
    metadata = {
        "import_details": [
            {"dll": "kernel32.dll", "function": "IsDebuggerPresent"},
            {"dll": "kernel32.dll", "function": "GetTickCount"},
        ],
    }
    analysis = {
        "sections": [{"name": ".text", "characteristics": 0xE0000020,
                      "entropy": 0.0, "raw_size": 512}],
        "extended": [],
    }

    emitted = {
        d["metadata"]["reason"]
        for d in _as_dicts(analyse_pe_heuristics(metadata, analysis))
        if d["value"] != "pe_structure_anomaly"
    }

    known = BEHAVIOURAL_REASONS | _reason_code_values()
    assert emitted <= known, (
        f"Unrecognised behavioural reason(s): {sorted(emitted - known)}. "
        "Add to BEHAVIOURAL_REASONS if intentional."
    )


# ==========================================================================
# SOURCE CONTRACT
# ==========================================================================

def test_no_validator_emits_a_top_level_reason_detail():
    """
    Static guard at the source. No validator may use ``reason`` as a top-level
    key in ``details`` - that is the reserved name the emission layer owns.
    Use ``sub_reason``.

    Catches the defect at authoring time, before any file is analysed, and
    covers validators that no fixture happens to exercise.
    """
    import pathlib
    import re

    validators_dir = pathlib.Path(
        "iocx/validators"
    )
    if not validators_dir.is_dir():  # pragma: no cover - path guard
        pytest.skip(f"validators directory not found at {validators_dir}")

    pattern = re.compile(r'["\']reason["\']\s*:')

    offenders = []
    for path in sorted(validators_dir.glob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        "Validators must not use a top-level 'reason' key in details "
        "(it is overwritten by the emission layer). Use 'sub_reason'.\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("colliding_key", ["reason"])
def test_det_parent_is_not_overwritable(colliding_key):
    """
    Directly pin ``_det``'s merge behaviour: a caller-supplied payload must not
    be able to overwrite the parent reason code.
    """
    from iocx.analysis.heuristics import _det

    det = _det("pe_structure_anomaly",
               ReasonCodes.LOAD_CONFIG_SEH_INVALID,
               {colliding_key: "attacker_controlled"})

    metadata = det.metadata if hasattr(det, "metadata") else det["metadata"]
    assert metadata["reason"] == ReasonCodes.LOAD_CONFIG_SEH_INVALID, (
        f"_det allowed a payload key '{colliding_key}' to overwrite the parent "
        "reason code."
    )
