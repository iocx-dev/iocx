# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.utils import detect_file_type, FileType


def test_detect_file_type_pe_mz(tmp_path):
    # MZ header and valid PE signature
    p = tmp_path / "pe.bin"
    p.write_bytes(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"+ b"PE\x00\x00")
    assert detect_file_type(str(p)) == FileType.PE


def test_detect_file_type_pe_fallback(tmp_path):
    # MZ header but no valid PE signature → reject
    p = tmp_path / "mz_only.bin"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    assert detect_file_type(str(p)) == FileType.UNKNOWN


def test_detect_file_type_pe_exception(monkeypatch, tmp_path):
    # Create a minimal MZ file so the PE block is entered
    p = tmp_path / "bad_pe.bin"
    p.write_bytes(b"MZ" + b"\x00" * 100)

    # Fake header object that raises inside __getitem__
    class BoomBytes(bytes):
        def __getitem__(self, key):
            raise ValueError("forced failure")

    # Monkeypatch open() to return our BoomBytes instead of real bytes
    def fake_open(*args, **kwargs):
        class FakeFile:
            def read(self, n):
                return BoomBytes(b"MZ" + b"\x00" * 100)
            def __enter__(self): return self
            def __exit__(self, *exc): pass
        return FakeFile()

    monkeypatch.setattr("builtins.open", fake_open)

    # Should hit the except block and return UNKNOWN
    assert detect_file_type(str(p)) == FileType.UNKNOWN


def test_detect_file_empty_header(tmp_path):
    # MZ header but no valid PE signature → reject
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert detect_file_type(str(p)) == FileType.UNKNOWN


def test_detect_file_type_elf(tmp_path):
    p = tmp_path / "elf.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert detect_file_type(str(p)) == FileType.ELF


def test_detect_file_type_macho(tmp_path):
    p = tmp_path / "macho.bin"
    p.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
    assert detect_file_type(str(p)) == FileType.MACHO


def test_detect_file_type_zip(tmp_path):
    p = tmp_path / "zip.bin"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    assert detect_file_type(str(p)) == FileType.ZIP


def test_detect_file_type_tar(tmp_path):
    p = tmp_path / "tar.bin"
    # TAR magic appears at offset 257
    data = bytearray(512)
    data[257:262] = b"ustar"
    p.write_bytes(data)
    assert detect_file_type(str(p)) == FileType.TAR


def test_detect_file_type_7z(tmp_path):
    p = tmp_path / "7z.bin"
    p.write_bytes(b"7z\xBC\xAF\x27\x1C" + b"\x00" * 100)
    assert detect_file_type(str(p)) == FileType.SEVEN_Z


def test_detect_file_type_text(tmp_path):
    p = tmp_path / "text.txt"
    p.write_text("hello world")
    assert detect_file_type(str(p)) == FileType.TEXT


def test_detect_file_type_binary_unknown(tmp_path):
    p = tmp_path / "bin.bin"
    p.write_bytes(b"\x00\xff\x10\x80" * 10)
    assert detect_file_type(str(p)) == FileType.UNKNOWN


def test_detect_file_type_open_exception(tmp_path):
    # Passing a directory triggers an exception on open()
    assert detect_file_type(str(tmp_path)) == FileType.UNKNOWN
