import re
import base64
import string
from ..detectors import register_detector

# Allow URL-safe base64 too: '-' and '_'
# Allow unpadded base64 (={0,2}).
# Prevents matching inside larger tokens (via lookbehind/lookahead).
BASE64_REGEX = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{4,}(?:={0,2})(?![A-Za-z0-9+/=_-])"
)

# Checks whether the decoded bytes are mostly printable characters.
def looks_like_text(decoded: bytes) -> bool:

    # Accept UTF-16LE (lots of null bytes)
    if b"\x00" in decoded:
        return True

    printable = sum(c in bytes(string.printable, "ascii") for c in decoded)
    return printable / max(len(decoded), 1) >= 0.7

def extract(text: str):
    results = []
    for match in BASE64_REGEX.findall(text):

        # Normalise to string
        # re.findall() may return bytes or str depending on input type. This ensures consistent handling.
        s = match if isinstance(match, str) else match.decode("ascii", "ignore")

        # Add padding if missing
        # This ensures decoding always works as URL‑safe base64 is often unpadded
        padded = s + "=" * (-len(s) % 4)

        try:
            # urlsafe handles both standard and URL-safe base64
            decoded_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            continue

        if not looks_like_text(decoded_bytes):
            continue

        decoded = decoded_bytes.decode("utf-8", errors="replace")
        results.append(f"{s} (decoded: {decoded})")

    return results

register_detector("base64", extract)
