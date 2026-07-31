# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Unit tests for iocx.parsers.pe_tls.

Strategy:
- Byte-level builders construct IMAGE_TLS_DIRECTORY structs (24-byte PE32 /
  40-byte PE32+) and NULL-terminated callback VA arrays via struct.pack.
- Fake PE objects expose OPTIONAL_HEADER.Magic / ImageBase /
  DATA_DIRECTORY[9] and get_data(), steering PE32-vs-PE32+ width, the
  VA->RVA callback conversion, and read failures / short reads at chosen
  RVAs (which a flat-image stub alone cannot produce).
- Determinism tests assert byte-for-byte stable output across runs.

Note: TLS address fields are VAs. Callback resolution subtracts ImageBase,
so fixtures use image_base = 0x400000 and callback VAs = image_base + RVA.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

import pytest

import iocx.parsers.pe_tls as M
from iocx.parsers.pe_tls import (
    build_tls_structure,
    _image_base,
    _is_pe32_plus,
    _locate_tls_directory,
    _raw_data_size,
    _read_callbacks,
    _read_directory,
    _MAGIC_PE32,
    _MAGIC_PE32_PLUS,
    _TLS_DIRECTORY_INDEX,
)

_IB = 0x400000  # ImageBase used throughout


# =================================================================
# Byte-level builders
# =================================================================

def _tls_dir(ptr_size: int, start: int, end: int, index: int,
             callbacks: int, zerofill: int = 0, chars: int = 0) -> bytes:
    fmt = "<QQQQII" if ptr_size == 8 else "<IIIIII"
    return struct.pack(fmt, start, end, index, callbacks, zerofill, chars)


def _cb_array(ptr_size: int, vas: List[int]) -> bytes:
    fmt = "<Q" if ptr_size == 8 else "<I"
    return b"".join(struct.pack(fmt, v) for v in vas) + struct.pack(fmt, 0)


# =================================================================
# Fake PE objects
# =================================================================

class _DataDir:
    def __init__(self, rva: int, size: int):
        self.VirtualAddress = rva
        self.Size = size


class _OptHdr:
    def __init__(self, dd: Optional[_DataDir], magic, image_base,
                 has_magic=True, has_image_base=True):
        self.DATA_DIRECTORY = [None] * 16
        if dd is not None:
            self.DATA_DIRECTORY[_TLS_DIRECTORY_INDEX] = dd
        if has_magic:
            self.Magic = magic
        if has_image_base:
            self.ImageBase = image_base


class _FakePE:
    """
    Flat-image PE: RVA == offset into `image`. get_data clamps to the buffer
    (producing short reads at the edge) and raises for any RVA in `raise_at`
    or beyond the buffer.
    """
    def __init__(self, image: bytes = b"",
                 dd: Optional[_DataDir] = None,
                 magic: int = _MAGIC_PE32,
                 image_base: int = _IB,
                 raise_at=(),
                 has_optional_header: bool = True,
                 has_magic: bool = True,
                 has_image_base: bool = True):
        self._img = bytearray(image)
        self._raise_at = set(raise_at)
        if has_optional_header:
            self.OPTIONAL_HEADER = _OptHdr(dd, magic, image_base,
                                           has_magic, has_image_base)

    def get_data(self, rva: int, length: int) -> bytes:
        if rva in self._raise_at:
            raise ValueError("boom")
        if rva < 0 or rva > len(self._img):
            raise ValueError("unmapped RVA")
        return bytes(self._img[rva:rva + length])


def _build_pe(ptr_size: int, *, tls_rva: int = 0x1000, cb_rva: int = 0x2000,
              start=_IB + 0x3000, end=_IB + 0x3000, callback_vas=None,
              image_size: int = 0x8000, magic=None,
              image_base: int = _IB, raise_at=()) -> _FakePE:
    """Assemble a PE with a TLS dir and (optional) callback array."""
    if magic is None:
        magic = _MAGIC_PE32_PLUS if ptr_size == 8 else _MAGIC_PE32
    callbacks_va = (image_base + cb_rva) if callback_vas is not None else 0
    directory = _tls_dir(ptr_size, start, end, image_base + 0x4000,
                         callbacks_va)
    image = bytearray(image_size)
    image[tls_rva:tls_rva + len(directory)] = directory
    if callback_vas is not None:
        arr = _cb_array(ptr_size, callback_vas)
        image[cb_rva:cb_rva + len(arr)] = arr
    dir_size = 40 if ptr_size == 8 else 24
    return _FakePE(bytes(image), _DataDir(tls_rva, dir_size), magic=magic,
                   image_base=image_base, raise_at=raise_at)


# =================================================================
# _locate_tls_directory
# =================================================================

class TestLocator:
    def test_valid(self):
        pe = _FakePE(dd=_DataDir(0x1000, 24))
        assert _locate_tls_directory(pe) == (0x1000, 24)

    def test_zero_rva_none(self):
        assert _locate_tls_directory(_FakePE(dd=_DataDir(0, 24))) is None

    def test_zero_size_none(self):
        assert _locate_tls_directory(_FakePE(dd=_DataDir(0x1000, 0))) is None

    def test_missing_optional_header_none(self):
        assert _locate_tls_directory(
            _FakePE(has_optional_header=False)) is None

    def test_missing_entry_none(self):
        assert _locate_tls_directory(_FakePE()) is None


# =================================================================
# _is_pe32_plus
# =================================================================

class TestIsPe32Plus:
    def test_pe32_plus_true(self):
        assert _is_pe32_plus(_FakePE(magic=_MAGIC_PE32_PLUS)) is True

    def test_pe32_false(self):
        assert _is_pe32_plus(_FakePE(magic=_MAGIC_PE32)) is False

    def test_missing_magic_defaults_false(self):
        assert _is_pe32_plus(_FakePE(has_magic=False)) is False

    def test_missing_optional_header_defaults_false(self):
        assert _is_pe32_plus(_FakePE(has_optional_header=False)) is False


# =================================================================
# _image_base
# =================================================================

class TestImageBase:
    def test_valid(self):
        assert _image_base(_FakePE(image_base=_IB)) == _IB

    def test_missing_none(self):
        assert _image_base(_FakePE(has_image_base=False)) is None

    def test_missing_optional_header_none(self):
        assert _image_base(_FakePE(has_optional_header=False)) is None


# =================================================================
# _read_directory
# =================================================================

class TestReadDirectory:
    def test_success_pe32(self):
        directory = _tls_dir(4, _IB + 0x100, _IB + 0x200, _IB + 0x300,
                             _IB + 0x400, 0x10, 0x20)
        pe = _FakePE(bytes(0x1000) + directory)
        errs: List[str] = []
        out = _read_directory(pe, 0x1000, 24, 4, errs)
        assert out == (_IB + 0x100, _IB + 0x200, _IB + 0x300, _IB + 0x400,
                       0x10, 0x20)
        assert errs == []

    def test_read_raises(self):
        pe = _FakePE(bytes(0x1000), raise_at={0x1000})
        errs: List[str] = []
        assert _read_directory(pe, 0x1000, 24, 4, errs) is None
        assert errs == ["tls_directory_read_failed"]

    def test_short_read_truncated(self):
        # image ends 10 bytes into the directory -> short read
        pe = _FakePE(bytes(0x1000 + 10))
        errs: List[str] = []
        assert _read_directory(pe, 0x1000, 24, 4, errs) is None
        assert errs == ["tls_directory_truncated"]

    def test_unpack_error_is_defensive(self, monkeypatch):
        # After the length guard there are always dir_size bytes, so
        # struct.unpack_from cannot fail with real input. Force it.
        orig = M.struct.unpack_from

        def boom(fmt, buf, off=0):
            if len(fmt) >= 7:  # the directory formats "<IIIIII"/"<QQQQII"
                raise struct.error("forced")
            return orig(fmt, buf, off)

        monkeypatch.setattr(M.struct, "unpack_from", boom)
        pe = _FakePE(bytes(0x1000) + bytes(24))
        errs: List[str] = []
        assert _read_directory(pe, 0x1000, 24, 4, errs) is None
        assert errs == ["tls_directory_unpack_failed"]


# =================================================================
# _raw_data_size
# =================================================================

class TestRawDataSize:
    def test_positive(self):
        errs: List[str] = []
        assert _raw_data_size(0x1000, 0x1100, errs) == 0x100
        assert errs == []

    def test_zero_length_valid(self):
        errs: List[str] = []
        assert _raw_data_size(0x1000, 0x1000, errs) == 0
        assert errs == []

    def test_end_before_start(self):
        errs: List[str] = []
        assert _raw_data_size(0x2000, 0x1000, errs) is None
        assert errs == ["tls_raw_data_end_before_start"]


# =================================================================
# _read_callbacks
# =================================================================

class TestReadCallbacks:
    def _flat(self, image: bytes, raise_at=()):
        return _FakePE(bytes(image), raise_at=raise_at)

    def test_zero_va_returns_empty(self):
        trunc: List[str] = []
        errs: List[str] = []
        assert _read_callbacks(self._flat(b""), 0, _IB, 4, trunc, errs) == []
        assert trunc == [] and errs == []

    def test_image_base_none(self):
        errs: List[str] = []
        out = _read_callbacks(self._flat(b""), _IB + 0x10, None, 4, [], errs)
        assert out == []
        assert errs == ["tls_image_base_unavailable"]

    def test_va_below_image_base(self):
        errs: List[str] = []
        out = _read_callbacks(self._flat(b""), _IB - 0x10, _IB, 4, [], errs)
        assert out == []
        assert errs == ["tls_callbacks_va_below_image_base"]

    def test_walk_pe32(self):
        arr = _cb_array(4, [_IB + 0x1111, _IB + 0x2222])
        image = bytearray(0x3000)
        image[0x2000:0x2000 + len(arr)] = arr
        out = _read_callbacks(self._flat(bytes(image)), _IB + 0x2000, _IB, 4,
                              [], [])
        assert out == [_IB + 0x1111, _IB + 0x2222]

    def test_walk_pe32_plus(self):
        arr = _cb_array(8, [_IB + 0x1111])
        image = bytearray(0x3000)
        image[0x2000:0x2000 + len(arr)] = arr
        out = _read_callbacks(self._flat(bytes(image)), _IB + 0x2000, _IB, 8,
                              [], [])
        assert out == [_IB + 0x1111]

    def test_read_raises(self):
        trunc: List[str] = []
        pe = self._flat(bytes(0x3000), raise_at={0x2000})
        out = _read_callbacks(pe, _IB + 0x2000, _IB, 4, trunc, [])
        assert out == []
        assert "tls_callbacks_read_failed" in trunc

    def test_short_read_truncated(self):
        # callback array sits 2 bytes before the image end -> short read
        trunc: List[str] = []
        image = bytearray(0x2000 + 2)  # only 2 bytes at rva 0x2000
        pe = self._flat(bytes(image))
        out = _read_callbacks(pe, _IB + 0x2000, _IB, 4, trunc, [])
        assert out == []
        assert "tls_callbacks_truncated" in trunc

    def test_unpack_error_is_defensive(self, monkeypatch):
        orig = M.struct.unpack_from

        def boom(fmt, buf, off=0):
            if fmt in ("<I", "<Q"):
                raise struct.error("forced")
            return orig(fmt, buf, off)

        monkeypatch.setattr(M.struct, "unpack_from", boom)
        arr = _cb_array(4, [_IB + 0x1111])
        image = bytearray(0x3000)
        image[0x2000:0x2000 + len(arr)] = arr
        trunc: List[str] = []
        out = _read_callbacks(self._flat(bytes(image)), _IB + 0x2000, _IB, 4,
                              trunc, [])
        assert out == []
        assert "tls_callbacks_unpack_failed" in trunc

    def test_max_callbacks_exceeded(self, monkeypatch):
        monkeypatch.setattr(M, "_MAX_CALLBACKS", 3)
        # 5 non-null callbacks, no terminator reached within the cap
        arr = b"".join(struct.pack("<I", _IB + i) for i in range(1, 6))
        image = bytearray(0x3000)
        image[0x2000:0x2000 + len(arr)] = arr
        trunc: List[str] = []
        out = _read_callbacks(self._flat(bytes(image)), _IB + 0x2000, _IB, 4,
                              trunc, [])
        assert len(out) == 3
        assert "tls_callbacks_max_exceeded" in trunc


# =================================================================
# build_tls_structure — full roundtrips & contract
# =================================================================

class TestBuildTlsStructure:
    def test_absent_returns_none(self):
        assert build_tls_structure(_FakePE(dd=None)) is None

    def test_directory_read_failed_dict(self):
        # dir present but get_data raises at the dir RVA -> fields None branch
        pe = _build_pe(4, raise_at={0x1000})
        out = build_tls_structure(pe)
        assert out["errors"] == ["tls_directory_read_failed"]
        assert out["start_address_of_raw_data"] is None
        assert out["callbacks"] == [] and out["callback_count"] == 0
        assert out["is_64bit"] is False

    def test_roundtrip_pe32_no_callbacks(self):
        # AddressOfCallBacks == 0 -> empty callbacks, zero-length raw valid
        pe = _build_pe(4, callback_vas=None,
                       start=_IB + 0x3000, end=_IB + 0x3000)
        out = build_tls_structure(pe)
        assert out["is_64bit"] is False
        assert out["address_of_callbacks"] == 0
        assert out["callbacks"] == []
        assert out["raw_data_size"] == 0
        assert out["errors"] == [] and out["truncations"] == []

    def test_roundtrip_pe32_with_callbacks(self):
        pe = _build_pe(4, callback_vas=[_IB + 0x1111, _IB + 0x2222],
                       start=_IB + 0x3000, end=_IB + 0x3100)
        out = build_tls_structure(pe)
        assert out["callback_count"] == 2
        assert out["callbacks"] == [_IB + 0x1111, _IB + 0x2222]
        assert out["raw_data_size"] == 0x100

    def test_roundtrip_pe32_plus_with_callbacks(self):
        pe = _build_pe(8, callback_vas=[_IB + 0xABCD])
        out = build_tls_structure(pe)
        assert out["is_64bit"] is True
        assert out["callbacks"] == [_IB + 0xABCD]

    def test_end_before_start_tombstone(self):
        pe = _build_pe(4, callback_vas=None,
                       start=_IB + 0x4000, end=_IB + 0x3000)
        out = build_tls_structure(pe)
        assert "tls_raw_data_end_before_start" in out["errors"]
        assert out["raw_data_size"] is None

    def test_contract_keys(self):
        pe = _build_pe(4, callback_vas=[_IB + 0x10])
        out = build_tls_structure(pe)
        for k in ("rva", "size", "is_64bit", "image_base",
                  "start_address_of_raw_data", "end_address_of_raw_data",
                  "address_of_index", "address_of_callbacks",
                  "size_of_zero_fill", "characteristics", "raw_data_size",
                  "callbacks", "callback_count", "truncations", "errors"):
            assert k in out

    def test_json_serializable(self):
        import json
        out = build_tls_structure(_build_pe(4, callback_vas=[_IB + 0x10]))
        json.dumps(out)  # must not raise


# =================================================================
# Determinism
# =================================================================

class TestDeterminism:
    def test_repeated_calls_identical(self):
        import json
        a = build_tls_structure(_build_pe(8, callback_vas=[_IB + 0x1, _IB + 0x2]))
        b = build_tls_structure(_build_pe(8, callback_vas=[_IB + 0x1, _IB + 0x2]))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
