import re
import functools
import idna
from ....models import Detection

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

@functools.lru_cache(maxsize=1024)
def _punycode_decodes_to_unicode(domain: str) -> bool:
    if domain[:4] != "xn--":
        return False
    try:
        decoded = idna.decode(domain)
    except idna.IDNAError:
        return True
    # Check for Unicode homoglyphs
    for c in decoded:
        if ord(c) > 127:
            return True
    return False


def extract_bare_domains(text: str):
    results: list[Detection] = []

    for m in BARE_DOMAIN_REGEX.finditer(text):
        domain = m.group(1)
        results.append(
            Detection(
                value=domain,
                start=m.start(1),
                end=m.end(1),
                category="domains",
                metadata={
                    "homoglyph_unicode": False,
                    "homoglyph_punycode": _punycode_decodes_to_unicode(domain),
                    "mixed_script": False
                }
            )
        )
    return results
