import re
import base64
from ..detectors import register_detector

# Strict base64 pattern: groups of 4 chars, optional padding, word boundaries
BASE64_REGEX = re.compile(
    r"(?<![A-Za-z0-9+/=])"          # left boundary
    r"([A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)"
    r"(?![A-Za-z0-9+/=])"           # right boundary
)

def safe_decode(s: str):
    try:
        # Add padding if missing
        padded = s + "=" * (-len(s) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except Exception:
        return None

def extract(text: str):
    results = []
    for match in BASE64_REGEX.findall(text):
        decoded = safe_decode(match)
        if decoded is not None:
            results.append(f"{match} (decoded: {decoded})")
    return results



register_detector("base64", extract)
