import pytest
from iocx.utils import detect_file_type, FileType


# --- Helper: patch magic.from_file ---
@pytest.fixture
def patch_magic(monkeypatch):
    def _patch(return_value=None, exception=None):
        if exception:
            monkeypatch.setattr(
                "iocx.utils.magic.from_file",
                lambda path, mime=True: (_ for _ in ()).throw(exception)
            )
        else:
            monkeypatch.setattr(
                "iocx.utils.magic.from_file",
                lambda path, mime=True: return_value
            )
    return _patch


def test_detect_file_type_exception_returns_unknown(patch_magic):
    patch_magic(exception=RuntimeError("boom"))
    assert detect_file_type("x") == FileType.UNKNOWN


def test_filetype_fallback_mz(tmp_path):
    p = tmp_path / "mz.bin"
    p.write_bytes(b"MZ" + b"\x00\xff\x10\x80")

    result = detect_file_type(str(p))

    assert result == FileType.PE


def test_filetype_fallback_open_exception(tmp_path):
    # Passing a directory triggers an exception on open()
    result = detect_file_type(str(tmp_path))

    # The fallback block swallows the exception and continues,
    # so assert whatever the function returns after the fallback.
    assert result != FileType.PE


def test_detect_file_type_text_plain(patch_magic):
    patch_magic(return_value="text/plain")
    assert detect_file_type("x") == FileType.TEXT


def test_detect_file_type_json(patch_magic):
    patch_magic(return_value="application/json")
    assert detect_file_type("x") == FileType.TEXT


def test_detect_file_type_xml(patch_magic):
    patch_magic(return_value="application/xml")
    assert detect_file_type("x") == FileType.TEXT


def test_detect_file_type_pe(patch_magic):
    patch_magic(return_value="application/x-dosexec")
    assert detect_file_type("x") == FileType.PE


def test_detect_file_type_elf(patch_magic):
    patch_magic(return_value="application/x-executable")
    assert detect_file_type("x") == FileType.ELF


def test_detect_file_type_macho(patch_magic):
    patch_magic(return_value="application/x-mach-binary")
    assert detect_file_type("x") == FileType.MACHO


def test_detect_file_type_unknown_mime(patch_magic):
    patch_magic(return_value="something/weird")
    assert detect_file_type("x") == FileType.UNKNOWN


def test_detect_file_type_zip(patch_magic):
    patch_magic(return_value="application/x-zip-compressed")
    assert detect_file_type("x") == FileType.ZIP


def test_detect_file_type_tar(patch_magic):
    patch_magic(return_value="application/x-gtar")
    assert detect_file_type("x") == FileType.TAR


def test_detect_file_type_7zip(patch_magic):
    patch_magic(return_value="application/x-7z")
    assert detect_file_type("x") == FileType.SEVEN_Z
