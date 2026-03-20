import re
from ....models import Detection

URL_REGEX = re.compile(
    r"""
    \b
    (?:https?|ftp)://                          # protocol
    (?:[a-zA-Z0-9\-._~%]+@)?                   # optional userinfo
    (?:
        (?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}     # domain
        |
        \d{1,3}(?:\.\d{1,3}){3}                # IPv4
        |
        \[[0-9a-fA-F:]+\]                      # IPv6
    )
    (?::\d{2,5})?                              # optional port
    (?:/[^\s<>"']*)?                           # optional path/query/fragment
    \b
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
