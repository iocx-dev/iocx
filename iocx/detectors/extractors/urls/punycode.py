import functools
import idna
import unicodedata

@functools.lru_cache(maxsize=1024)
def _punycode_decodes_to_unicode(domain: str) -> bool:
    if not domain.lower().startswith("xn--"):
        return False
    try:
        decoded = idna.decode(domain)
    except idna.IDNAError:
        return False

    return any(ord(c) > 127 for c in decoded)


@functools.lru_cache(maxsize=1024)
def _decode_punycode(domain: str):
    """Return decoded Unicode domain or None."""
    if not domain.lower().startswith("xn--"):
        return None
    try:
        decoded = idna.decode(domain)
        return decoded
    except idna.IDNAError:
        return None


def _detect_script(s: str) -> str:
    """Return Latin / Cyrillic / Greek / Mixed / Unknown."""
    scripts = set()

    for ch in s:
        if ord(ch) < 128:
            continue # ASCII → Latin
        name = unicodedata.name(ch, "")
        if "CYRILLIC" in name:
            scripts.add("Cyrillic")
        elif "GREEK" in name:
            scripts.add("Greek")
        else:
            scripts.add("Other")

    if not scripts:
        return "Latin"
    if len(scripts) == 1:
        return scripts.pop()
    return "Mixed"


def _contains_confusables(s: str) -> bool:
    """Detect if Unicode characters are visually confusable with ASCII."""
    # Simple heuristic: any non-ASCII in Latin-like scripts is suspicious
    for ch in s:
        if ord(ch) < 128:
            continue
        name = unicodedata.name(ch, "")
        if any(tag in name for tag in ("CYRILLIC", "GREEK")):
            return True
    return False
