# Appendix 3.13 – Crypto Strings Adversarial Specification

- **File:** `crypto_strings_adversarial.full.bin`
- **Layer: 3** — `Adversarial`

# Purpose

A synthetic text‑based fixture designed to validate IOCX’s extraction of **cryptocurrency wallet identifiers under adversarial conditions**. This sample mixes valid and invalid BTC/ETH patterns, noise‑embedded strings, and near‑miss formats to ensure the extractor remains deterministic, avoids false positives, and handles malformed inputs safely.

This fixture specifically targets the robustness of the **Base58Check** and **hex‑based** wallet detectors.

# Behaviours exercised

This fixture intentionally includes:

- **Valid ETH addresses**
   - Three syntactically valid 40‑hex‑character Ethereum addresses
   - Embedded in noise, brackets, and mixed contexts
   - Ensures ETH extraction is stable and case‑insensitive
- **Invalid or near‑miss ETH patterns**
   - 39‑character truncated address
   - Address containing non‑hex characters
   - Ensures ETH extractor rejects malformed patterns
- **BTC Base58Check adversarial patterns**
   - One well‑known example BTC address (`1BoatSLRHtKNngkdXEeobR76b53LETtpy`)
      - Checksum‑invalid by design
   - Shortened BTC‑like strings
   - Base58‑looking noise
   - Ensures BTC extractor performs **checksum validation**, not regex‑only matching
- **Noise‑embedded patterns**
   - BTC/ETH‑like substrings surrounded by arbitrary characters
   - Ensures extractor does not over‑match or break on surrounding text

# Contract enforced

Under `analysis_level = full`, IOCX must:

- Extract:
   - Only the three valid ETH addresses
- Not extract:
   - Any BTC addresses (all are invalid under Base58Check)
   - Any near‑miss ETH patterns
   - Any Base58‑looking noise
- Maintain:
   - Deterministic output ordering
   - Stable JSON formatting
   - No false positives

This fixture verifies that the crypto extractor correctly enforces **Base58Check** for BTC and strict hex‑length validation for ETH.
