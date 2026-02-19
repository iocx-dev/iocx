import re

def extract_strings(path, min_length=4):

    with open(path, "rb") as f:
        data = f.read()

    ascii_strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    unicode_strings = re.findall(rb"(?:[\x20-\x7E]\x00){%d,}" % min_length, data)

    decoded = [s.decode("latin-1", errors="ignore") for s in ascii_strings]
    decoded += [s.decode("utf-16", errors="ignore") for s in unicode_strings]

    return decoded

def extract_strings_from_bytes(data, min_length=4):
    results = []

    # ASCII
    for match in re.findall(rb"[ -~]{%d,}" % min_length, data):
        results.append(match.decode("latin-1", errors="ignore"))

    # UTF-16LE (tolerant)
    try:
        decoded_utf16 = data.decode("utf-16le", errors="ignore")
        for match in re.findall(r"[ -~]{%d,}" % min_length, decoded_utf16):
            results.append(match)
    except Exception:
        pass

    return results

