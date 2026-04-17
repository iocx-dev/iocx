# Appendix 3.2 — Crypto Entropy Payload Sample Specification

- **File:** `crypto_entropy_payload.full.exe`
- **Layer: 3** `Adversarial PE (high-entropy section)`

## Purpose:

- Validate IOCX’s ability to handle high-entropy custom sections.
- Ensure no false-positive IOC extraction.
- Ensure rich header parsing is stable and JSON-safe.

## Expected Characteristics:

- Contains a custom section named `.crypt`.
- `.crypt` section entropy >= 5.5.
- No URLs, domains, IPs, emails, hashes, or crypto addresses.
- No anti-debug heuristics.
- Rich header must be present and fully hex-encoded.
