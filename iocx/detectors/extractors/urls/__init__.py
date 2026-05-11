# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from ...registry import register_detector
from ....models import Detection
from .strict_url import extract_strict_urls
from .bare_domain import extract_bare_domains
from .deobfuscate import deobfuscate_text
from .normalise import normalise_url


def extract(text: str):
    clean = deobfuscate_text(text)

    urls: list[Detection] = []
    domains: list[Detection] = []

    seen_urls = set()
    seen_domains = set()

    # STRICT URLS
    for det in extract_strict_urls(clean):
        value = det.value if isinstance(det, Detection) else det[0]
        start = det.start if isinstance(det, Detection) else det[1]
        end = det.end if isinstance(det, Detection) else det[2]

        norm = normalise_url(value)
        if not norm:
            continue

        if norm not in seen_urls:
            seen_urls.add(norm)
            urls.append(Detection(norm, start, end, "urls"))

    # BARE DOMAINS
    for det in extract_bare_domains(clean):
        value = det.value if isinstance(det, Detection) else det[0]
        start = det.start if isinstance(det, Detection) else det[1]
        end = det.end if isinstance(det, Detection) else det[2]

        norm = normalise_url(value)
        if not norm:
            continue

        if norm not in seen_domains:
            seen_domains.add(norm)
            domains.append(Detection(norm, start, end, "domains"))

    return {
        "urls": urls,
        "domains": domains,
    }

register_detector("urls", extract)
