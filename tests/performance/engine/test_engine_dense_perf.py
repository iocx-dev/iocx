import time
import pytest
from iocx.engine import Engine
from pathlib import Path

FIXTURE = Path("tests/integration/fixtures/bin/pe_dense.exe")

@pytest.mark.performance
def test_engine_dense_pe():
    engine = Engine()
    engine._analysis_level = "full"

    start = time.perf_counter()
    result = engine.extract(FIXTURE)
    end = time.perf_counter()

    duration = end - start
    print(f"[perf] engine dense PE: {duration:.4f}s")

    # sanity check
    assert "iocs" in result
