import magic

class FileType:
    TEXT = "text"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"


def detect_file_type(path: str) -> str:
    """
    Uses python-magic to detect the file type in order to route to the correct parser.
    """
    try:
        mime = magic.from_file(path, mime=True)
    except Exception:
        return FileType.UNKNOWN

    if mime in ("text/plain", "application/json", "application/xml"):
        return FileType.TEXT

    if mime == "application/x-dosexec":
        return FileType.PE

    if mime == "application/x-executable":
        return FileType.ELF

    if mime == "application/x-mach-binary":
        return FileType.MACHO

    return FileType.UNKNOWN
