from ...detectors import register_detector
from .strict_url import extract_strict_urls
from .bare_domain import extract_bare_domains
from .deobfuscate import deobfuscate_text
from .normalise import normalise_url

def extract(text: str):
    # 1. Deobfuscate common patterns
    clean = deobfuscate_text(text)

    # 2. Extract strict URLs (with protocol)
    urls = extract_strict_urls(clean)

    # 3. Extract bare domains
    domains = extract_bare_domains(clean)

    # 4. Normalise
    urls = [normalise_url(u) for u in urls]
    domains = [normalise_url(d) for d in domains]

    # 5. Deduplicate while preserving order
    def dedupe(seq):
        seen = set()
        out = []
        for item in seq:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    urls = dedupe(urls)
    domains = dedupe(domains)

    return {
        "urls": urls,
        "domains": domains,
    }

# register on import
register_detector("urls", extract)
