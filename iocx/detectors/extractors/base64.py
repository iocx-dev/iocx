import re
import base64
import string
from ..registry import register_detector
from ...models import Detection

# Accepts standard + URL‑safe base64
# Handles missing padding
# Avoids matching inside larger tokens
# Decodes safely
# Filters by “looks like text”
# Requires min. length of 12
BASE64_REGEX = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{12,}(?:={0,2})(?![A-Za-z0-9+/=_-])"
)

# Checks whether the decoded bytes are mostly printable characters.
def looks_like_text(decoded: bytes) -> bool:
    # Detect UTF‑16LE: null bytes in every odd position
    if len(decoded) > 2 and all(decoded[i] == 0 for i in range(1, len(decoded), 2)): # pragma: no cover
        return True # pragma: no cover

    printable = sum(c in bytes(string.printable, "ascii") for c in decoded)
    return printable / max(len(decoded), 1) >= 0.85


def extract(text: str):
    results: list[Detection] = []

    for m in BASE64_REGEX.finditer(text):
        raw = m.group(0)

        # Normalise to string
        # re.findall() may return bytes or str depending on input type. This ensures consistent handling.
        s = raw if isinstance(raw, str) else raw.decode("ascii", "ignore")

        # Add padding if missing
        # This ensures decoding always works as URL‑safe base64 is often unpadded
        padded = s + "=" * (-len(s) % 4)

        try:
            # urlsafe handles both standard and URL-safe base64
            decoded_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            continue

        # reject control characters
        if any(c < 9 or (13 < c < 32) for c in decoded_bytes):
            continue

        # require at least one alphabetic character
        if not any(chr(c).isalpha() for c in decoded_bytes):
            continue

        if not looks_like_text(decoded_bytes):
            continue

        decoded = decoded_bytes.decode("utf-8", errors="replace")
        results.append(
            Detection(
                value=s,
                start=m.start(),
                end=m.end(),
                category="base64",
                metadata={"decoded": decoded}
                )
            )

    return results

register_detector("base64", extract)
