# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import time
import pytest
from iocx.engine import Engine

@pytest.mark.performance
def test_engine_end_to_end_1mb():
    engine = Engine()

    # Generate 1MB of mixed content
    data = (
        "http://example.com " * 2000 +
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BadApp " * 200 +
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT " * 200 +
        "91.210.45.12 " * 200
    )
    data = data[:1_000_000] # ensure exactly ~1MB

    start = time.perf_counter()
    result = engine.extract(data)
    end = time.perf_counter()

    duration = end - start
    print(f"[perf] engine end-to-end 1MB: {duration:.4f}s")

    # sanity check
    assert "iocs" in result
