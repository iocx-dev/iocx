import re
from ....models import Detection
from .homoglyph_punycode import _punycode_decodes_to_unicode, _decode_punycode, _detect_script, _contains_confusables

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

def extract_bare_domains(text: str):
    results: list[Detection] = []

    for m in BARE_DOMAIN_REGEX.finditer(text):
        domain = m.group(1)

        unicode_decoded = _decode_punycode(domain)
        unicode_flag = _punycode_decodes_to_unicode(domain)

        script = _detect_script(unicode_decoded) if unicode_decoded else "Latin"
        confusables = _contains_confusables(unicode_decoded) if unicode_decoded else False

        results.append(
            Detection(
                value=domain,
                start=m.start(1),
                end=m.end(1),
                category="domains",
                metadata={
                    "punycode": domain.lower().startswith("xn--"),
                    "punycode_decodes_to_unicode": unicode_flag,
                    "decoded_unicode": unicode_decoded,
                    "contains_confusables": confusables,
                    "script": script,
                }
            )
        )
    return results
