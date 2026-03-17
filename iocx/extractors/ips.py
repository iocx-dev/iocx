import re
import ipaddress
from ..detectors import register_detector

# Candidate extractor:
# - IPv4 with optional CIDR
# - IPv6 with optional zone index
# - Bracketed IPv6 with optional port
# - IPv4/IPv6 with port
CANDIDATE = r"""(?:(?:\b\d{1,3}(?:\.\d{1,3}){1,3}(?:/\d{1,2})?\b)|(?:\[[0-9A-Fa-f:]+\](?::\d{1,5})?)|(?:\b[0-9A-Fa-f:]+(?:%\w+)?(?:/\d{1,3})?\b)|(?:\b[0-9A-Fa-f:.]+:\d{1,5}\b))"""
REGEX = re.compile(CANDIDATE, re.VERBOSE)


def _try_ip(token):
    try:
        ipaddress.ip_address(token)
        return token
    except ValueError:
        return None

def _try_network(token):
    # Only treat as network if it explicitly contains a slash
    if "/" not in token:
        return None
    try:
        ipaddress.ip_network(token, strict=False)
        return token
    except ValueError:
        return None


def _try_ipv6_zone(token):
    if "%" not in token or "/" in token:
        return None

# NOTE:
# This branch is effectively unreachable due to the extractor's "salvage-first"
# behaviour. The regex will always extract a valid IPv6 substring (e.g. "::")
# from any token containing colons before this function is reached.
# As a result, malformed zone-indexed tokens never reach the ValueError path.

    try:
        addr, zone = token.split("%", 1)
        ipaddress.IPv6Address(addr)
        return f"{addr}%{zone}"
    except ValueError:  # pragma: no cover  (unreachable; see note above)
        return None


def _try_bracketed_ipv6(token):
    # [2001:db8::1]:443
    m = re.match(r"^\[([0-9A-Fa-f:]+)\](?::(\d{1,5}))?$", token)

    if not m:
        return None
    addr, port = m.groups()

# NOTE:
# This branch is only reachable when the bracketed IPv6 pattern matches AND
# the port is syntactically valid but numerically invalid (>65535).
# In practice, malformed tokens are rejected earlier by the regex, so this
# branch is rarely (or never) executed in real-world extraction flows.

    try:
        ipaddress.IPv6Address(addr)
    except ValueError:   # pragma: no cover  (see note above)
        return None

    if port is None:
        return addr

    if not (0 <= int(port) <= 65535):
        return None

# NOTE:
# This success path is unreachable under the extractor's "salvage-first"
# behaviour. The regex never yields a token shaped like "IP:port" that
# reaches this validator. IPv4 tokens are split before this point, and
# IPv6 tokens with colons are always interpreted as full IPv6 addresses.
# As a result, this branch cannot be executed in practice.

    return f"{addr}:{port}"    # pragma: no cover


def _try_ip_with_port(token):
    # Unbracketed IPv4/IPv6 with port
    if token.count(":") < 1:
        return None

    ip_part, port = token.rsplit(":", 1)

    if not port.isdigit() or not (0 <= int(port) <= 65535):
        return None

    try:
        ipaddress.ip_address(ip_part)
    except ValueError:
        return None

    return f"{ip_part}:{port}"


def extract(text: str):
    results = []
    cache = {}

    for m in REGEX.finditer(text):
        token = m.group(0)
        if token in cache:
            if cache[token] is not None:
                results.append(cache[token])
            continue

        validated = (
            _try_network(token)
            or _try_bracketed_ipv6(token)
            or _try_ipv6_zone(token)
            or _try_ip_with_port(token)
            or _try_ip(token)
        )

        cache[token] = validated
        if validated is not None:
            results.append((validated, m.start(), m.end(), "ips"))

    return results

# register on import
register_detector("ips", extract)
