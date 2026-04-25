import re
import hashlib
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


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_MAP = {c: i for i, c in enumerate(BASE58_ALPHABET)}

def base58check_decode(addr: str) -> bytes:
    """Decode Base58Check and return version+payload bytes."""
    num = 0
    for char in addr:
        if char not in BASE58_MAP:
            raise ValueError("Invalid Base58 character")
        num = num * 58 + BASE58_MAP[char]

    # Convert to bytes
    full_bytes = num.to_bytes((num.bit_length() + 7) // 8, "big")

    # Add leading zero bytes for each leading '1'
    n_pad = len(addr) - len(addr.lstrip("1"))
    full_bytes = b"\x00" * n_pad + full_bytes

    if len(full_bytes) < 5:
        raise ValueError("Too short for Base58Check")

    payload, checksum = full_bytes[:-4], full_bytes[-4:]

    hashed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if checksum != hashed[:4]:
        raise ValueError("Invalid checksum")

    return payload # version + data


def is_valid_btc_address(addr: str) -> bool:
    try:
        decoded = base58check_decode(addr)
    except Exception:
        return False

    # Must be 21 bytes: 1 version + 20 payload
    if len(decoded) != 21:
        return False

    version = decoded[0]
    return version in (0x00, 0x05)


def extract(text: str):
    detections: list[Detection] = []

    # Legacy BTC
    for m in BTC_LEGACY_RE.finditer(text):
        candidate = m.group(0)
        if is_valid_btc_address(candidate):
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
