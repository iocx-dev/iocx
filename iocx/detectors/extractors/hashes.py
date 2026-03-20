import re
from ..registry import register_detector
from ...models import Detection

HASH_REGEX = re.compile(
    r"\b("
    r"[a-fA-F0-9]{32}"      # MD5
    r"|[a-fA-F0-9]{40}"     # SHA1
    r"|[a-fA-F0-9]{64}"     # SHA256
    r"|[a-fA-F0-9]{128}"    # SHA512
    r"|[a-fA-F0-9]{8,31}"   # generic short hex (keys, IDs, partial hashes)
    r")\b"
)

def extract(text: str):
    results: list[Detection] = []

    for m in HASH_REGEX.finditer(text):
        results.append(
            Detection(
                value=m.group(1),
                start=m.start(1),
                end=m.end(1),
                category="hashes",
            )
        )

    return results

register_detector("hashes", extract)
