import re
from ..detectors import register_detector

HASH_REGEX = re.compile(
    r"\b("
    r"[a-fA-F0-9]{32}"      # MD5
    r"|[a-fA-F0-9]{40}"     # SHA1
    r"|[a-fA-F0-9]{64}"     # SHA256
    r"|[a-fA-F0-9]{128}"    # SHA512
    r")\b"
)

def extract(text: str):
    """Extract cryptographic hashes from text."""
    return HASH_REGEX.findall(text)

# register on import
register_detector("hashes", extract)
