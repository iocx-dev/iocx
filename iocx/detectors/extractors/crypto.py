import re
from ..registry import register_detector
from iocx.models import Detection

# Legacy Base58 BTC
BTC_LEGACY_RE = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")

# Bech32 + Taproot BTC (bc1q..., bc1p...)
BTC_BECH32_RE = re.compile(
    r"\bbc1[qp][a-z0-9]{11,71}\b"
)

# ETH (mixed-case checksum or lowercase)
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


def extract(text: str):
    detections = []

    # Legacy BTC
    for m in BTC_LEGACY_RE.finditer(text):
        detections.append(
            Detection(
                value=m.group(0),
                category="crypto.btc",
                start=m.start(),
                end=m.end(),
            )
        )

    # Bech32 / Taproot BTC
    for m in BTC_BECH32_RE.finditer(text):
        detections.append(
            Detection(
                value=m.group(0),
                category="crypto.btc",
                start=m.start(),
                end=m.end(),
            )
        )

    # ETH
    for m in ETH_RE.finditer(text):
        detections.append(
            Detection(
                value=m.group(0),
                category="crypto.eth",
                start=m.start(),
                end=m.end(),
            )
        )

    return detections


register_detector("crypto", extract)
