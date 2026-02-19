import re
from ..detectors import register_detector

DOMAIN_REGEX = re.compile(
    r"""
    \b
    (?:[A-Za-z0-9-]+\.)+
    (?!dll\b|exe\b|sys\b|startup\b|text\b|pdata\b|xdata\b|rdata\b)
    [A-Za-z]{3,63}
    \b
    """,
    re.VERBOSE | re.IGNORECASE,
)

def extract(text):
    return DOMAIN_REGEX.findall(text)

# register on import
register_detector("domains", extract)

