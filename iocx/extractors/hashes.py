import re
from ..detectors import register_detector

HASH_REGEX = re.compile(
    r"\b("
    r"[a-fA-F0-9]{32}"      # MD5
    r"|[a-fA-F0-9]{40}"     # SHA1
    r"|[a-fA-F0-9]{64}"     # SHA256
    r"|[a-fA-F0-9]{128}"    # SHA512
    r"|[a-fA-F0-9]{8,31}" # generic short hex (keys, IDs, partial hashes)
    r")\b"
)

def extract(text: str):
    results = []
    for m in HASH_REGEX.finditer(text):
        results.append((m.group(1), m.start(1), m.end(1), "hashes"))
    return results


# register on import
register_detector("hashes", extract)
