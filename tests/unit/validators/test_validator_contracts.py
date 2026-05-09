# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import inspect
from iocx.validators import STRUCTURAL_VALIDATORS
from iocx.validators.schema import StructuralIssue

def test_all_validators_have_depends_on():
    missing = [
        name for name, fn in STRUCTURAL_VALIDATORS.items()
        if not hasattr(fn, "_depends_on")
    ]

    assert not missing, (
        "All validators must declare dependencies via @depends_on. "
        f"Missing: {', '.join(missing)}"
    )

def test_validator_dependencies_match_signature():
    errors = []

    for name, fn in STRUCTURAL_VALIDATORS.items():
        deps = getattr(fn, "_depends_on", ("metadata", "analysis"))
        sig = inspect.signature(fn)
        params = list(sig.parameters)

        if len(deps) != len(params):
            errors.append((name, deps, params))

    assert not errors, (
        "Validator dependency declarations must match function signatures. "
        f"Errors: {errors}"
    )

def test_dispatcher_argument_order():
    from iocx.validators import run_structural_validators

    class Marker:
        pass

    internal = Marker()
    metadata = Marker()
    analysis = Marker()

    calls = {}

    # Monkeypatch validators to capture calls
    patched = {}
    for name, fn in STRUCTURAL_VALIDATORS.items():
        def make_wrapper(fn, name):
            def wrapper(*args):
                calls[name] = args
                return []
            wrapper._depends_on = getattr(fn, "_depends_on", ("metadata", "analysis"))
            return wrapper

        patched[name] = make_wrapper(fn, name)

    # Replace validators temporarily
    original = STRUCTURAL_VALIDATORS.copy()
    STRUCTURAL_VALIDATORS.clear()
    STRUCTURAL_VALIDATORS.update(patched)

    try:
        run_structural_validators(internal, metadata, analysis)
    finally:
        # Restore original validators
        STRUCTURAL_VALIDATORS.clear()
        STRUCTURAL_VALIDATORS.update(original)

    # Validate argument order
    for name, args in calls.items():
        deps = patched[name]._depends_on
        expected = []
        if "internal" in deps:
            expected.append(internal)
        if "metadata" in deps:
            expected.append(metadata)
        if "analysis" in deps:
            expected.append(analysis)

        assert list(args) == expected, (
            f"Dispatcher passed incorrect args to {name}: "
            f"expected {expected}, got {args}"
        )

def test_validator_return_types():
    internal = {}
    metadata = {}
    analysis = {}

    for name, fn in STRUCTURAL_VALIDATORS.items():
        deps = getattr(fn, "_depends_on", ("metadata", "analysis"))

        args = []
        if "internal" in deps:
            args.append(internal)
        if "metadata" in deps:
            args.append(metadata)
        if "analysis" in deps:
            args.append(analysis)

        result = fn(*args)

        assert isinstance(result, list), f"{name} must return a list"
        for item in result:
            assert isinstance(item, StructuralIssue), (
                f"{name} returned non‑StructuralIssue: {item}"
            )
