from iocx.validators import STRUCTURAL_VALIDATORS

def test_all_structural_validators_declare_dependencies():
    missing = []

    for name, fn in STRUCTURAL_VALIDATORS.items():
        if not hasattr(fn, "_depends_on"):
            missing.append(name)

    assert not missing, (
        "All structural validators must declare dependencies via @depends_on. "
        f"Missing: {', '.join(missing)}"
    )
