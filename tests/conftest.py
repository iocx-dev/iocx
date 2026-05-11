# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from dataclasses import dataclass

@pytest.fixture
def simple_detector():
    """A minimal detector plugin for registry lookup tests."""
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Meta:
        id: str = "simple-detector"
        name: str = "Simple Detector"
        version: str = "0.1.0"
        description: str = "Simple test detector"
        author: str = "Test"
        capabilities: list[str] = ("detector",)
        iocx_min_version: str = "0.0.0"

    class SimpleDetector:
        def __init__(self):
            self.metadata = Meta()

        def detect(self, text, ctx):
            return []

    return SimpleDetector()


@pytest.fixture
def exploding_transformer():

    @dataclass(frozen=True)
    class Meta:
        id: str = "exploding-transformer"
        name: str = "Exploding Transformer"
        version: str = "0.1.0"
        description: str = "Always raises"
        author: str = "Test"
        capabilities: list[str] = ("transformer",)
        iocx_min_version: str = "0.0.0"

    class ExplodingTransformer:
        def __init__(self):
            self.metadata = Meta()

        def transform(self, text, ctx):
            raise RuntimeError("boom")

    return ExplodingTransformer()


@pytest.fixture
def exploding_detector():

    @dataclass(frozen=True)
    class Meta:
        id: str = "exploding-detector"
        name: str = "Exploding Detector"
        version: str = "0.1.0"
        description: str = "Always raises"
        author: str = "Test"
        capabilities: list[str] = ("detector",)
        iocx_min_version: str = "0.0.0"

    class ExplodingDetector:
        def __init__(self):
            self.metadata = Meta()

        def detect(self, text, ctx):
            raise RuntimeError("boom")

    return ExplodingDetector()


@pytest.fixture
def tuple_detector():

    @dataclass(frozen=True)
    class Meta:
        id: str = "tuple-detector"
        name: str = "Tuple Detector"
        version: str = "0.1.0"
        description: str = "Returns a valid 4‑tuple"
        author: str = "Test"
        capabilities: list[str] = ("detector",)
        iocx_min_version: str = "0.0.0"

    class TupleDetector:
        def __init__(self):
            self.metadata = Meta()

        def detect(self, text, ctx):
            # value, start, end, category
            return [("abc", 0, 3, "tuplecat")]

    return TupleDetector()


@pytest.fixture
def malformed_detector():

    @dataclass(frozen=True)
    class Meta:
        id: str = "malformed-detector"
        name: str = "Malformed Detector"
        version: str = "0.1.0"
        description: str = "Returns malformed items"
        author: str = "Test"
        capabilities: list[str] = ("detector",)
        iocx_min_version: str = "0.0.0"

    class MalformedDetector:
        def __init__(self):
            self.metadata = Meta()

        def detect(self, text, ctx):
            return [
                123, # invalid type → else branch
                ("bad", 0, 3), # wrong tuple length → else branch
                {"foo": "bar"}, # invalid shape → else branch
            ]

    return MalformedDetector()


@pytest.fixture
def malformed_detector():
    """Detector that returns malformed items → triggers the else: continue block."""

    @dataclass(frozen=True)
    class Meta:
        id: str = "malformed-detector"
        name: str = "Malformed Detector"
        version: str = "0.1.0"
        description: str = "Returns malformed items"
        author: str = "Test"
        capabilities: list[str] = ("detector",)
        iocx_min_version: str = "0.0.0"

    class MalformedDetector:
        def __init__(self):
            self.metadata = Meta()

        def detect(self, text, ctx):
            return [
                123, # invalid type → else branch
                ("bad", 0, 3), # wrong tuple length → else branch
                {"foo": "bar"}, # invalid shape → else branch
                object(), # completely invalid → else branch
            ]

    return MalformedDetector()
