# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Deterministic VS_VERSIONINFO extraction.

This module is intentionally independent of the resource-tree parser so that
version-info concerns live in their own layer with their own fixtures and
reason codes.

Output contract:
    None                        - no RT_VERSION resource present (not an error)
    dict with keys:
        rva, size               - placement of the chosen VS_VERSIONINFO blob
        decoded                 - True if the top-level header was unpackable
        header_ok               - szKey == "VS_VERSION_INFO"
        length_consistent       - wLength fits within the blob
        fixed_file_info         - dict or None
        string_file_info        - list of StringFileInfo dicts (possibly empty)
        var_file_info           - list of VarFileInfo dicts (possibly empty)
        errors                  - list of per-substructure tombstone tags
"""

from typing import Dict, Any, List, Optional, Tuple
import struct

RT_VERSION = 16
_VS_VERSION_INFO_KEY = "VS_VERSION_INFO"
_VS_FFI_SIGNATURE = 0xFEEF04BD
_VS_FFI_STRUCT_VERSION = 0x00010000


def build_version_info(pe) -> Optional[Dict[str, Any]]:
    """
    Locate and decode the first RT_VERSION leaf in the resource tree.

    Deterministic ordering: leaves are sorted by (name_id, language_id)
    with non-integer keys pushed to the end, so the choice of "first"
    leaf is stable across runs.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    leaf = _find_first_version_leaf(pe.DIRECTORY_ENTRY_RESOURCE)
    if leaf is None:
        return None

    try:
        rva = int(leaf.data.struct.OffsetToData)
        size = int(leaf.data.struct.Size)
    except (AttributeError, struct.error):
        return {
            "rva": None, "size": None,
            "decoded": False, "header_ok": False, "length_consistent": False,
            "fixed_file_info": None,
            "string_file_info": [], "var_file_info": [],
            "errors": ["leaf_struct_unpack"],
        }

    try:
        raw = bytes(pe.get_data(rva, size))
    except Exception:
        return {
            "rva": rva, "size": size,
            "decoded": False, "header_ok": False, "length_consistent": False,
            "fixed_file_info": None,
            "string_file_info": [], "var_file_info": [],
            "errors": ["read_failed"],
        }

    decoded = _decode_vs_versioninfo(raw)
    decoded["rva"] = rva
    decoded["size"] = size
    return decoded


# =================================================================
# Locator
# =================================================================

def _find_first_version_leaf(root_dir):
    leaves: List[Tuple[Any, Any, Any]] = []
    try:
        for type_entry in root_dir.entries:
            if getattr(type_entry, "id", None) != RT_VERSION:
                continue
            if not hasattr(type_entry, "directory"):
                continue
            for name_entry in type_entry.directory.entries:
                name_key = getattr(name_entry, "id", None)
                if not hasattr(name_entry, "directory"):
                    continue
                for lang_entry in name_entry.directory.entries:
                    if not hasattr(lang_entry, "data"):
                        continue
                    lang_key = getattr(lang_entry, "id", None)
                    leaves.append((name_key, lang_key, lang_entry))
    except (AttributeError, IndexError):
        return None

    if not leaves:
        return None

    _SENTINEL = 1 << 31

    def _key(t):
        n, l, _ = t
        return (n if isinstance(n, int) else _SENTINEL,
                l if isinstance(l, int) else _SENTINEL)

    leaves.sort(key=_key)
    return leaves[0][2]


# =================================================================
# Decoder
# =================================================================

def _align4(n: int) -> int:
    return (n + 3) & ~3


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _read_utf16_sz(buf: bytes, off: int) -> Tuple[str, int]:
    """Read a NUL-terminated UTF-16LE string. Returns (text, bytes_consumed_inc_NUL)."""
    end = off
    while end + 1 < len(buf):
        if buf[end] == 0 and buf[end + 1] == 0:
            break
        end += 2
    s = buf[off:end].decode("utf-16-le", errors="replace")
    return s, (end - off) + 2


def _decode_vs_versioninfo(buf: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "decoded": False,
        "header_ok": False,
        "length_consistent": False,
        "w_type": None,
        "fixed_file_info": None,
        "string_file_info": [],
        "var_file_info": [],
        "errors": [],
    }

    if len(buf) < 6:
        out["errors"].append("too_short")
        return out

    try:
        w_length = _u16(buf, 0)
        w_value_length = _u16(buf, 2)
        w_type = _u16(buf, 4)
    except struct.error:
        out["errors"].append("header_unpack")
        return out

    out["decoded"] = True
    out["w_type"] = w_type
    out["length_consistent"] = 6 <= w_length <= len(buf)

    key_str, key_consumed = _read_utf16_sz(buf, 6)
    out["header_ok"] = (key_str == _VS_VERSION_INFO_KEY)

    pos = _align4(6 + key_consumed)

    # ---- VS_FIXEDFILEINFO (52 bytes when present) ----
    if w_value_length >= 52 and pos + w_value_length <= len(buf):
        try:
            ffi = struct.unpack_from("<13I", buf, pos)
            (sig, sver, fv_ms, fv_ls, pv_ms, pv_ls,
             flags_mask, flags, file_os, ftype, fsubtype,
             dt_ms, dt_ls) = ffi
            out["fixed_file_info"] = {
                "signature": sig,
                "signature_ok": sig == _VS_FFI_SIGNATURE,
                "struct_version": sver,
                "struct_version_ok": sver == _VS_FFI_STRUCT_VERSION,
                "file_version": (fv_ms, fv_ls),
                "product_version": (pv_ms, pv_ls),
                "file_flags_mask": flags_mask,
                "file_flags": flags,
                "file_os": file_os,
                "file_type": ftype,
                "file_subtype": fsubtype,
                "file_date": (dt_ms, dt_ls),
            }
        except struct.error:
            out["errors"].append("fixed_file_info_unpack")
    elif w_value_length != 0:
        out["errors"].append("fixed_file_info_truncated")

    pos = _align4(pos + w_value_length)

    end = min(w_length, len(buf)) if out["length_consistent"] else len(buf)

    # ---- Children: StringFileInfo / VarFileInfo ----
    while pos + 6 <= end:
        try:
            c_len = _u16(buf, pos)
            _c_vlen = _u16(buf, pos + 2)
            _c_type = _u16(buf, pos + 4)
        except struct.error:
            out["errors"].append("child_header_unpack")
            break

        if c_len < 6 or pos + c_len > end:
            out["errors"].append("child_length_invalid")
            break

        key_str, key_consumed = _read_utf16_sz(buf, pos + 6)
        body_start = _align4(pos + 6 + key_consumed)
        child_end = pos + c_len

        if key_str == "StringFileInfo":
            out["string_file_info"].append(
                _decode_string_file_info(buf, body_start, child_end)
            )
        elif key_str == "VarFileInfo":
            out["var_file_info"].append(
                _decode_var_file_info(buf, body_start, child_end)
            )
        else:
            out["errors"].append("unknown_child")

        pos = _align4(child_end)

    return out


def _decode_string_file_info(buf: bytes, start: int, end: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {"tables": [], "errors": []}
    pos = start
    while pos + 6 <= end:
        try:
            t_len = _u16(buf, pos)
        except struct.error:
            result["errors"].append("string_table_header")
            return result
        if t_len < 6 or pos + t_len > end:
            result["errors"].append("string_table_length")
            return result

        key_str, key_consumed = _read_utf16_sz(buf, pos + 6)
        body_start = _align4(pos + 6 + key_consumed)
        body_end = pos + t_len

        table: Dict[str, Any] = {
            "lang_codepage": key_str,
            "strings": {},
            "errors": [],
        }
        # StringTable key must be 8 hex chars: <langID><codepage>
        if len(key_str) != 8 or any(c not in "0123456789ABCDEFabcdef" for c in key_str):
            table["errors"].append("lang_codepage_key")

        sp = body_start
        while sp + 6 <= body_end:
            try:
                s_len = _u16(buf, sp)
            except struct.error:
                table["errors"].append("string_header")
                break
            if s_len < 6 or sp + s_len > body_end:
                table["errors"].append("string_length")
                break
            sk, sk_used = _read_utf16_sz(buf, sp + 6)
            val_start = _align4(sp + 6 + sk_used)
            val_end = sp + s_len
            if val_end > val_start:
                sv, _ = _read_utf16_sz(buf, val_start)
            else:
                sv = ""
            # Bound stored strings to keep the dict deterministic in size
            table["strings"][sk[:128]] = sv[:512]
            sp = _align4(val_end)

        result["tables"].append(table)
        pos = _align4(body_end)

    return result


def _decode_var_file_info(buf: bytes, start: int, end: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {"vars": [], "errors": []}
    pos = start
    while pos + 6 <= end:
        try:
            v_len = _u16(buf, pos)
            v_vlen = _u16(buf, pos + 2)
        except struct.error:
            result["errors"].append("var_header")
            return result
        if v_len < 6 or pos + v_len > end:
            result["errors"].append("var_length")
            return result

        key_str, key_consumed = _read_utf16_sz(buf, pos + 6)
        val_start = _align4(pos + 6 + key_consumed)
        val_end = pos + v_len

        if v_vlen % 4 != 0:
            result["errors"].append("translation_not_dword_aligned")

        translations = []
        nd = (val_end - val_start) // 4
        for i in range(nd):
            try:
                lang, cp = struct.unpack_from("<HH", buf, val_start + 4 * i)
                translations.append({"lang": lang, "codepage": cp})
            except struct.error:
                result["errors"].append("translation_unpack")
                break

        result["vars"].append({"key": key_str, "translations": translations})
        pos = _align4(val_end)

    return result
