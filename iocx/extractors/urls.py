import re
from ..detectors import register_detector

URL_REGEX = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)

def extract(text: str):
    return URL_REGEX.findall(text)

# register on import
register_detector("urls", extract)
