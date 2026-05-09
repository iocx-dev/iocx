# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import time
import pytest
from iocx.engine import Engine
from pathlib import Path

FIXTURE = Path("tests/contract/fixtures/layer3_adversarial/franken_malformed_pe.full.exe")

@pytest.mark.performance
def test_engine_franken_pe():
    engine = Engine()

    start = time.perf_counter()
    result = engine.extract(FIXTURE)
    end = time.perf_counter()

    duration = end - start
    print(f"[perf] engine franken PE: {duration:.4f}s")

    # sanity check
    assert "iocs" in result
