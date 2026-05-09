import pytest
from iocx.schemas.internal_schema import InternalMetadata
from iocx.engine import Engine
from iocx import validators

@pytest.fixture
def minimal_pe_path(request):
    root = request.config.rootpath
    return str(root / "tests" / "integration" / "fixtures" / "bin" / "pe_rsrc.exe")

def test_internal_metadata_schema(minimal_pe_path):
    engine = Engine()
    engine._analysis_level = "full"

    engine._pipeline_pe(minimal_pe_path)

    internal = engine._internal_metadata

    assert "resources_struct" in internal
    root = internal["resources_struct"]["root"]

    assert isinstance(root["rva"], int)
    assert isinstance(root["size"], int)
    assert isinstance(root["entries"], list)
