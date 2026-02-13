from typing import Callable, Dict, List

DetectorFunc = Callable[[str], List[str]]

_DETECTORS: Dict[str, DetectorFunc] = {}

def register_detector(name: str, func: DetectorFunc):
    if name in _DETECTORS:
        raise ValueError(f"Detector '{name}' already registered")
    _DETECTORS[name] = func

def get_detector(name: str) -> DetectorFunc:
    return _DETECTORS[name]

def all_detectors() -> Dict[str, DetectorFunc]:
    return dict(_DETECTORS)

# Import extractors so they register themselves
from . import extractors
