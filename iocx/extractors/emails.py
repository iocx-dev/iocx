import re
from ..detectors import register_detector

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

def extract(text: str):
    return EMAIL_REGEX.findall(text)

# register on import
register_detector("emails", extract)
