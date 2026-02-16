import pytest
from iocx.engine import Engine, EngineConfig

@pytest.fixture
def engine():
    return Engine(EngineConfig(enable_cache=False))

def test_extract_from_text(engine):
    text = "Visit http://malx-labs.example"

    # instantiate the engine and test through it
    result = engine.extract(text)
    assert "http://malx-labs.example" in result["iocs"]["urls"]
