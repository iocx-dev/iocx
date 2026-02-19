import re

# Bare domains like: example.com, sub.domain.co.uk, malx.io
BARE_DOMAIN_REGEX = re.compile(
    r"""
    \b
    (?:[A-Za-z0-9-]+\.)+                 # one or more labels
    (?!dll\b|exe\b|sys\b|startup\b|text\b|pdata\b|xdata\b|rdata\b)
    [A-Za-z]{2,63}                       # TLD (syntactic only)
    \b
    """,
    re.VERBOSE | re.IGNORECASE,
)


def extract_bare_domains(text: str) -> list[str]:
    return BARE_DOMAIN_REGEX.findall(text)
