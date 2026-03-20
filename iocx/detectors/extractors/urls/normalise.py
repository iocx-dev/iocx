from urllib.parse import urlparse, urlunparse


def normalise_url(url: str) -> str:
    """
    Basic normalisation:
    - lowercase scheme and host
    - strip trailing dots from host
    """
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").rstrip(".").lower()

    # If url was a bare domain (no scheme), treat it as netloc
    if not scheme and not netloc and parsed.path:
        netloc = parsed.path.rstrip(".").lower()
        path = ""
    else:
        path = parsed.path or ""

    normalised = urlunparse(
        (
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    # If we only had a bare domain, return just that
    if not scheme and not path and not parsed.query and not parsed.fragment:
        return netloc

    return normalised
