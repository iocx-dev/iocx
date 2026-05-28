# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

class FileType:
    TEXT = "text"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    ZIP = "zip"
    TAR = "tar"
    SEVEN_Z = "7z"
    UNKNOWN = "unknown"


def detect_file_type(path: str) -> str:
    """
    Pure‑Python file type detection.
    Removes dependency on python‑magic for full Windows portability.
    """

    try:
        with open(path, "rb") as f:
            header = f.read(4096)
    except Exception:
        return FileType.UNKNOWN

    if not header:
        return FileType.UNKNOWN

    # -------------------------
    # PE (Portable Executable)
    # ----------------------------------------------------------------------
    # WHY WE VERIFY THE HEADER
    #
    # A file beginning with "MZ" is not enough to classify it as a PE.
    # Windows itself performs two checks before treating a file as a valid
    # Portable Executable:
    #
    # 1. DOS header magic: "MZ"
    # 2. e_lfanew at 0x3C: offset to the real PE header
    # 3. PE signature at offset: "PE\0\0"
    #
    # If any of these checks fail, Windows will not load the binary.
    #
    # IOCX mirrors this behaviour. Returning FileType.PE triggers expensive
    # static analysis (entropy, imports, heuristics, section walking, etc).
    # We therefore only classify a file as PE when it meets the same minimal
    # structural requirements that Windows enforces.
    #
    # This prevents:
    # - wasted analysis on intentionally corrupted or spoofed "MZ" files
    # - attacker‑driven DoS via fake PE headers
    # - false positives from truncated or malformed binaries
    #
    # If a file claims to be "MZ" but fails verification, we treat it as
    # UNKNOWN rather than PE, because Windows would reject it as well.
    # ----------------------------------------------------------------------
    if header.startswith(b"MZ"):
        try:
            # Need at least up to 0x3C + 4 bytes for e_lfanew
            if len(header) >= 0x40:
                pe_offset = int.from_bytes(header[0x3C:0x40], "little")
                # Ensure PE header lies within the bytes we actually read
                if 0 <= pe_offset <= len(header) - 4:
                    if header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                        return FileType.PE
            return FileType.UNKNOWN
        except Exception:
            return FileType.UNKNOWN

    # -------------------------
    # ELF
    # -------------------------
    if header.startswith(b"\x7fELF"):
        return FileType.ELF

    # -------------------------
    # Mach‑O (fat + thin)
    # -------------------------
    macho_magic = (
        b"\xfe\xed\xfa\xce", # 32‑bit
        b"\xfe\xed\xfa\xcf", # 64‑bit
        b"\xce\xfa\xed\xfe", # reverse
        b"\xcf\xfa\xed\xfe", # reverse 64
        b"\xca\xfe\xba\xbe", # fat
        b"\xbe\xba\xfe\xca", # fat reverse
    )
    if header[:4] in macho_magic:
        return FileType.MACHO

    # -------------------------
    # ZIP
    # -------------------------
    if header.startswith(b"PK\x03\x04"):
        return FileType.ZIP

    # -------------------------
    # TAR (ustar)
    # -------------------------
    if b"ustar" in header:
        return FileType.TAR

    # -------------------------
    # 7z
    # -------------------------
    if header.startswith(b"7z\xBC\xAF\x27\x1C"):
        return FileType.SEVEN_Z

    # -------------------------
    # Text detection
    # -------------------------
    try:
        header.decode("utf-8")
        return FileType.TEXT
    except UnicodeDecodeError:
        return FileType.UNKNOWN
