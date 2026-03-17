from ...detectors import register_detector
from .strict_url import extract_strict_urls
from .bare_domain import extract_bare_domains
from .deobfuscate import deobfuscate_text
from .normalise import normalise_url

def extract(text: str):
    clean = deobfuscate_text(text)

    results = []

    # Strict URLs
    for value, start, end, _ in extract_strict_urls(clean):
        norm = normalise_url(value)
        if norm:
            results.append((norm, start, end, "urls"))

    # Bare domains
    for value, start, end, _ in extract_bare_domains(clean):
        norm = normalise_url(value)
        if norm:
            results.append((norm, start, end, "domains"))

    return results

register_detector("urls", extract)
