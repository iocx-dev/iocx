import magic

class FileType:
    TEXT = "text"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"


def detect_file_type(path: str) -> str:
    try:
        mime = magic.from_file(path, mime=True)
    except Exception:
        mime = ""

    # Text detection
    if mime in ("text/plain", "application/json", "application/xml"):
        return FileType.TEXT

    # Try PE detection via magic
    if "dosexec" in mime or "msdownload" in mime or "portable-executable" in mime:
        return FileType.PE

    # Fallback: check for MZ header
    try:
        with open(path, "rb") as f:
            if f.read(2) == b"MZ":
                return FileType.PE
    except Exception:
        pass

    # ELF / Mach-O
    if mime == "application/x-executable":
        return FileType.ELF

    if mime == "application/x-mach-binary":
        return FileType.MACHO

    return FileType.UNKNOWN


def spans_overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def suppress_overlaps(matches):
    """
    matches: list of (value, start, end)
    returns: list of (value, start, end) with overlaps removed
    """

    # Sort by start position, then by longest match first
    matches = sorted(matches, key=lambda m: (m[1], -(m[2] - m[1])))

    accepted = []
    occupied = []

    for value, start, end in matches:
        # Check if this span overlaps any accepted span
        if any(not (end <= s or start >= e) for (_, s, e) in accepted):
            continue

        accepted.append((value, start, end))

    return accepted

