import time
import pytest
from iocx.engine import Engine
from pathlib import Path

FIXTURE = Path("tests/contract/fixtures/layer1_core/clean_iocx_demo.core.exe")

@pytest.mark.performance
def test_engine_typical_pe():
    engine = Engine()

    start = time.perf_counter()
    result = engine.extract(FIXTURE)
    end = time.perf_counter()

    duration = end - start
    print(f"[perf] engine typical PE: {duration:.4f}s")

    # sanity check
    assert "iocs" in result


@pytest.mark.performance
def test_engine_typical_pe_heuristics():
    engine = Engine()
    engine._analysis_level = "full"

    start = time.perf_counter()
    result = engine.extract(FIXTURE)
    end = time.perf_counter()

    duration = end - start
    print(f"[perf] engine typical (with heuristics) PE: {duration:.4f}s")

    # sanity check
    assert "iocs" in result
