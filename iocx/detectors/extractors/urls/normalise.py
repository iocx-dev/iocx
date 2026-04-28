from urllib.parse import urlparse, urlunparse

def normalise_url(url: str) -> str:
    """
    IOC‑safe URL normalisation:
    - lowercase scheme
    - lowercase hostname only
    - preserve username, password, port
    - strip trailing dots from hostname
    - preserve path/query/fragment case
    - treat bare domains correctly
    """
    try:
        parsed = urlparse(url)
    except:
        return None

    # Lowercase scheme
    scheme = (parsed.scheme or "").lower()

    # Extract netloc components: userinfo@host:port
    netloc = parsed.netloc or ""
    userinfo = ""
    hostport = netloc

    if "@" in netloc:
        userinfo, hostport = netloc.split("@", 1)

    # Split host and port
    host = hostport
    port = ""

    # IPv6 literal: [::1]
    if hostport.startswith("["):
        if "]" in hostport:
            host, rest = hostport.split("]", 1)
            host += "]" # keep brackets
            if rest.startswith(":"):
                port = rest[1:]
    else:
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)

    # Lowercase only the hostname
    cleaned_host = host.rstrip(".").lower()

    # Rebuild netloc
    rebuilt_netloc = ""
    if userinfo:
        rebuilt_netloc += userinfo + "@"
    rebuilt_netloc += cleaned_host
    if port:
        rebuilt_netloc += ":" + port

    # Bare domain means:
    # - no scheme
    # - no netloc
    # - path contains the domain
    # - no query or fragment
    if (
        not scheme
        and not netloc
        and parsed.path
        and not parsed.query
        and not parsed.fragment
    ):
        # parsed.path contains the domain
        return parsed.path.rstrip(".").lower()

    # Rebuild full URL
    return urlunparse((
        scheme,
        rebuilt_netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
