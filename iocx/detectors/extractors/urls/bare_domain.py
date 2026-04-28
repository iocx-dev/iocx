import re
import functools
import idna
from ....models import Detection

REAL_TLDS = (
    "ae|ai|am|app|ar|au|be|bid|biz|blog|br|bz|ca|cam|cc|cf|ch|cl|click|cm|co|com|cz|"
    "date|de|dev|es|fi|fm|fr|fun|ga|gg|gl|gq|hk|hu|id|ie|in|info|io|ir|it|jp|kim|"
    "kr|kz|la|life|link|live|loan|ly|me|men|ml|mom|mx|net|nl|no|nz|online|org|party|"
    "paste|pe|ph|pl|pro|pt|pw|rest|review|ro|ru|sa|se|sg|sh|site|sk|store|su|tech|"
    "th|tk|to|top|trade|tr|tv|tw|ua|uk|us|uz|ve|vip|vn|win|world|ws|xyz|za"
)

BAD_TLDS = (
    "dll|exe|sys|text|startup|pdata|xdata|rdata|sh|"
    "bat|cmd|ps1|vbs|js|json|xml|ini|cfg|tmp|bak|log|dat|bin"
)

BARE_DOMAIN_REGEX = re.compile(
    rf"""
    (?<![A-Za-z0-9@]) # left boundary

    ( # capture domain
        (?:xn--[A-Za-z0-9-]+|[A-Za-z0-9-]+)
        (?:\.(?:xn--[A-Za-z0-9-]+|[A-Za-z0-9-]+))* # subdomains
        \.
        (?!{BAD_TLDS}\b)
        (?:xn--[A-Za-z0-9-]+|{REAL_TLDS})
    )

    (?=[^A-Za-z0-9._-]|$) # right boundary
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
