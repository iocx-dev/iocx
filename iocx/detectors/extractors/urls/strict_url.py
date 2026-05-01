import re
from ....models import Detection

URL_REGEX = re.compile(
    r"""
    (?i) # case-insensitive
    \b
    (?:https?|ftps?|sftp):// # scheme

    (?:[A-Za-z0-9\-._~%!$&'()*+,;=:]+@)? # optional userinfo

    ( # host
        (?: # domain
            (?:[A-Za-z0-9-]+\.)+
            (?:xn--[A-Za-z0-9-]+|[A-Za-z]{2,63})
        )
        |
        (?:\d{1,3}(?:\.\d{1,3}){3}) # IPv4
        |


\[ # IPv6 literal
            [0-9A-Fa-f:.%]+ # allow IPv4-mapped, zone index
        \]


    )

    (?::\d{2,5})? # optional port

    (?:/[^\s<>"']*)? # optional path
    (?:\?[^\s<>"']*)? # optional query
    (?:\#[^\s<>"']*)? # optional fragment (escaped #)
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
