import re

REAL_TLDS = (
    "com|net|org|io|co|uk|gov|edu|mil|info|biz|dev|app|ai|"
    "xyz|online|site|tech|store|blog|me|us|ca|de|fr|jp|cn|bar"
)

BAD_TLDS = "dll|exe|sys|text|startup|pdata|xdata|rdata|sh"

BARE_DOMAIN_REGEX = re.compile(
    rf"""
    (?<![A-Za-z0-9@.])                     # strong left boundary (blocks emails + inside words + dotted junk)

    (                                      # capture domain
        (?:xn--[A-Za-z0-9-]+|[A-Za-z0-9-]+)
        (?:\.(?:xn--[A-Za-z0-9-]+|[A-Za-z0-9-]+))*   # subdomains
        \.
        (?!{BAD_TLDS}\b)                   # block file extensions
        (?:xn--[A-Za-z0-9-]+|{REAL_TLDS})  # real TLDs
    )

    (?![A-Za-z0-9._-])                     # strong right boundary
    """,
    re.VERBOSE | re.IGNORECASE,
)

def extract_bare_domains(text: str):
    results = []
    for m in BARE_DOMAIN_REGEX.finditer(text):
        domain = m.group(1)
        results.append((domain, m.start(1), m.end(1), "domains"))
    return results


