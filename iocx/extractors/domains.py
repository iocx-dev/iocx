import re
from ..detectors import register_detector

DOMAIN_REGEX = re.compile(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

def extract(text):
    return DOMAIN_REGEX.findall(text)

# register on import
register_detector("domains", extract)
