import re

ASCII_RE = rb"[ -~]{%d,}"
UTF16LE_RE = rb"(?:[\x20-\x7E]\x00){%d,}"

# 50 KB cap
MAX_STRING_LEN = 50 * 1024

def extract_strings(path, min_length=4):
    with open(path, "rb") as f:
        data = f.read()
    return extract_strings_from_bytes(data, min_length)


def extract_strings_from_bytes(data, min_length=4):
    results = []

    # ASCII
    for match in re.findall(ASCII_RE % min_length, data):
        if len(match) <= MAX_STRING_LEN:
            results.append(match.decode("latin-1", errors="ignore"))

    # UTF-16LE (strict)
    for match in re.findall(UTF16LE_RE % min_length, data):
        if len(match) <= MAX_STRING_LEN * 2: # UTF-16 uses 2 bytes per char
            results.append(match.decode("utf-16le", errors="ignore"))

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for s in results:
        if s not in seen:
            seen.add(s)
            deduped.append(s)

    return deduped
