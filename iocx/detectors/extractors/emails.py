import re
from ..registry import register_detector
from ...models import Detection

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

def extract(text: str):
    results: list[Detection] = []

    for m in EMAIL_REGEX.finditer(text):
        results.append(
            Detection(
                m.group(0),
                m.start(),
                m.end(),
                "emails"
                )
            )
    return results

# register on import
register_detector("emails", extract)
