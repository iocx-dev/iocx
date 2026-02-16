import re

# Bare domains like: example.com, sub.domain.co.uk, malx.io
BARE_DOMAIN_REGEX = re.compile(
    r"""
    \b
    (?:[a-zA-Z0-9-]+\.)+       # one or more labels
    [a-zA-Z]{2,63}             # TLD
    (?!\.)                     # must NOT be followed by a dot
    """,
    re.VERBOSE,
)


def extract_bare_domains(text: str) -> list[str]:
    return BARE_DOMAIN_REGEX.findall(text)
