import re

def extract_strings(path, min_length=4):

    with open(path, "rb") as f:
        data = f.read()

    ascii_strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    unicode_strings = re.findall(rb"(?:[\x20-\x7E]\x00){%d,}" % min_length, data)

    decoded = [s.decode("latin-1", errors="ignore") for s in ascii_strings]
    decoded += [s.decode("utf-16", errors="ignore") for s in unicode_strings]

    return decoded
