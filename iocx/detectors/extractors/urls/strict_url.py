import re
from ....models import Detection

URL_REGEX = re.compile(
    r"""
    (?i) # case‑insensitive for scheme + host
    \b
    (?:https?|ftp):// # protocol
    (?:[A-Za-z0-9\-._~%]+@)? # optional userinfo
    (?:
        (?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63} # domain
        |
        \d{1,3}(?:\.\d{1,3}){3} # IPv4
        |


\[[0-9A-Fa-f:]+\]

                    # IPv6
    )
    (?::\d{2,5})? # optional port
    (?:/[^\s<>"']*)? # optional path/query/fragment
    """,
    re.VERBOSE,
)

def extract_strict_urls(text: str):
    results: list[Detection] = []

    for m in URL_REGEX.finditer(text):
        results.append(
            Detection(
                value=m.group(0),
                start=m.start(),
                end=m.end(),
                category="urls"
                )
            )
    return results
