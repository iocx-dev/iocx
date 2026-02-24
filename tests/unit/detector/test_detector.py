import pytest
from iocx.detectors import register_detector, get_detector, all_detectors

def test_register_and_get_detector():
    # fresh registry for test isolation
    # detectors import happens at module import time, so we patch the internal dict
    from iocx import detectors
    detectors._DETECTORS.clear()

    def fake(text):
        return ["x"]

    register_detector("fake", fake)
    assert get_detector("fake") is fake


def test_register_detector_duplicate_raises():
    from iocx import detectors
    detectors._DETECTORS.clear()

    def f(text):
        return ["x"]

    register_detector("dup", f)

    with pytest.raises(ValueError):
        register_detector("dup", f)


def test_all_detectors_returns_copy_not_reference():
    from iocx import detectors
    detectors._DETECTORS.clear()

    def f(text):
        return ["x"]

    register_detector("one", f)

    d = all_detectors()
    assert d == {"one": f}

    # mutate returned dict
    d["two"] = lambda x: ["y"]

    # internal registry must remain unchanged
    assert "two" not in detectors._DETECTORS
    assert detectors._DETECTORS == {"one": f}
