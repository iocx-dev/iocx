# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from importlib import import_module

_DETECTORS = {}
_LOADED = False

def _ensure_loaded():
    global _LOADED
    if not _LOADED or not _DETECTORS:
        import_module("iocx.detectors.extractors")
        _LOADED = True

def register_detector(name, fn):
    _ensure_loaded()
    _DETECTORS[name] = fn

def all_detectors():
    _ensure_loaded()
    return dict(_DETECTORS)

def get_detector(name):
    _ensure_loaded()
    return _DETECTORS.get(name)
