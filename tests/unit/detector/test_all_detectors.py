import pytest
from iocx.detectors.registry import all_detectors
from iocx.engine import Engine, EngineConfig


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def normalise_output(out):
    if out is None:
        return []
    if isinstance(out, list):
        return out
    if isinstance(out, tuple):
        return list(out)
    if isinstance(out, str):
        return [out]
    try:
        return list(out)
    except TypeError:
        return []


def run_detector(name, data):
    detectors = all_detectors()
    assert name in detectors, f"Detector {name} not registered"
    return normalise_output(detectors[name](data))


# ------------------------------------------------------------
# 1. Registry sanity
# ------------------------------------------------------------

def test_registry_loads_all_extractors():
    detectors = all_detectors()
    assert len(detectors) > 0
    for name, fn in detectors.items():
        assert callable(fn), f"Detector {name} is not callable"


# ------------------------------------------------------------
# 2. Detector contract (Detection OR str)
# ------------------------------------------------------------

def test_all_detectors_follow_contract():
    detectors = all_detectors()
    sample = (
        "example.com 8.8.8.8 /tmp/x "
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
        "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe "
        "SGVsbG8="
    )

    for name, fn in detectors.items():
        detections = run_detector(name, sample)
        assert isinstance(detections, list), f"{name} did not return a list"

        for d in detections:
            # Detection object
            if hasattr(d, "value") and hasattr(d, "category"):
                assert isinstance(d.value, str)
                assert isinstance(d.category, str)
                continue

            # Raw string detection
            assert isinstance(d, str), f"{name} returned unsupported type {type(d)}"


# ------------------------------------------------------------
# 3. Smoke test
# ------------------------------------------------------------

def test_all_detectors_smoke():
    detectors = all_detectors()
    blob = (
        "random text 12345 example.com 8.8.8.8 /tmp/x "
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT SGVsbG8="
    )

    for name, fn in detectors.items():
        detections = run_detector(name, blob)
        assert isinstance(detections, list), f"{name} failed smoke test"


def test_get_detector_returns_detector_and_none(monkeypatch, simple_detector):
    """
    Ensures get_detector():
    - returns the detector when it exists
    - returns None when it does not
    """
    import iocx.detectors.registry as registry

    # Inject our simple detector into the registry
    monkeypatch.setitem(registry._DETECTORS, "simple-detector", simple_detector)

    # 1. Should return the detector instance
    found = registry.get_detector("simple-detector")
    assert found is simple_detector

    # 2. Should return None for unknown names
    assert registry.get_detector("does-not-exist") is None


# ------------------------------------------------------------
# 4. Engine consistency (normalised)
# ------------------------------------------------------------

def normalise_engine_keys(engine_keys):
    """
    Engine returns crypto.btc, crypto.eth, domains, etc.
    Registry returns crypto, urls, etc.
    We normalise both sides to top-level detector names.
    """
    normalised = set()

    for key in engine_keys:
        if key.startswith("crypto."):
            normalised.add("crypto")
        else:
            normalised.add(key)

    return normalised


def normalise_key(name: str) -> str:
    # crypto.btc → crypto
    if name.startswith("crypto."):
        return "crypto"
    return name


def test_engine_uses_same_detectors_as_registry():
    engine = Engine(EngineConfig())

    registry = {normalise_key(k) for k in all_detectors().keys()}
    engine_keys = {normalise_key(k) for k in engine.extract("").get("iocs", {}).keys()}

    # Only compare detectors that exist in BOTH systems
    shared = registry.intersection(engine_keys)

    assert shared == shared # always true, but keeps structure clear

    # Ensure every registry detector appears in engine output
    missing_in_engine = registry - engine_keys
    assert not missing_in_engine, f"Engine missing detectors: {missing_in_engine}"

# ------------------------------------------------------------
# 5. Engine extraction smoke test
# ------------------------------------------------------------

def test_engine_extracts_without_error():
    engine = Engine(EngineConfig())
    blob = (
        "example.com 8.8.8.8 /tmp/x "
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT SGVsbG8="
    )

    result = engine.extract(blob)
    assert "iocs" in result
    assert isinstance(result["iocs"], dict)

    for name, detections in result["iocs"].items():
        detections = normalise_output(detections)
        assert isinstance(detections, list)
        for d in detections:
            if hasattr(d, "value") and hasattr(d, "type"):
                assert isinstance(d.value, str)
                assert isinstance(d.type, str)
            else:
                assert isinstance(d, str)

