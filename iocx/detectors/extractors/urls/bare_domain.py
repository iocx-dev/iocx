import re
import unicodedata
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

# ---------------------------------------------------------
# Homoglyph detection helpers
# ---------------------------------------------------------

def is_unicode_homoglyph(domain: str) -> bool:
    """True if domain contains any non‑ASCII characters."""
    return any(ord(c) > 127 for c in domain)


def punycode_decodes_to_unicode(domain: str) -> bool:
    """True if punycode decodes into Unicode (homoglyph attack)."""
    if not domain.startswith("xn--"):
        return False
    try:
        decoded = idna.decode(domain)
        return any(ord(c) > 127 for c in decoded)
    except idna.IDNAError:
        # invalid punycode = suspicious
        return True


def is_mixed_script(domain: str) -> bool:
    """Detect mixed-script domains (rare but dangerous)."""
    scripts = set()
    for c in domain:
        if ord(c) <= 127:
            continue
        try:
            scripts.add(unicodedata.name(c).split()[0])
        except ValueError:
            continue
    return len(scripts) > 1


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
                    "homoglyph_unicode": is_unicode_homoglyph(domain),
                    "homoglyph_punycode": punycode_decodes_to_unicode(domain),
                    "mixed_script": is_mixed_script(domain)
                }
            )
        )
    return results
