from ...detectors import register_detector
from ...models import Detection
from .strict_url import extract_strict_urls
from .bare_domain import extract_bare_domains
from .deobfuscate import deobfuscate_text
from .normalise import normalise_url


def extract(text: str):
    clean = deobfuscate_text(text)
    results: list[Detection] = []

    # Strict URLs
    for det in extract_strict_urls(clean):
        value = det.value if isinstance(det, Detection) else det[0]
        start = det.start if isinstance(det, Detection) else det[1]
        end   = det.end   if isinstance(det, Detection) else det[2]

        norm = normalise_url(value)
        if norm:
            results.append(
                Detection(
                    value=norm,
                    start=start,
                    end=end,
                    category="urls",
                )
            )

    # Bare domains
    for det in extract_bare_domains(clean):
        value = det.value if isinstance(det, Detection) else det[0]
        start = det.start if isinstance(det, Detection) else det[1]
        end   = det.end   if isinstance(det, Detection) else det[2]

        norm = normalise_url(value)
        if norm:
            results.append(
                Detection(
                    value=norm,
                    start=start,
                    end=end,
                    category="domains",
                )
            )

    return results


register_detector("urls", extract)
