# Appendix 3.17 – Crypto Strings Adversarial Specification

- **File:** `crypto_strings_adversarial.full.bin`
- **Layer: 3** — `Adversarial`

# Purpose

This adversarial fixture validates IOCX’s extraction of **cryptocurrency wallet identifiers** under noisy, malformed, and intentionally misleading conditions. It ensures that the crypto detector:

- extracts only syntactically valid ETH addresses
- rejects all malformed or near‑miss ETH patterns
- performs full **Base58Check** validation for BTC
- does not produce false positives from Base58‑looking noise
- remains deterministic and stable across adversarial input

The fixture is designed to confirm that the crypto extractor is **strict, checksum‑aware, and resilient** to misleading patterns.

# Behaviours exercised

This sample intentionally mixes valid, invalid, and adversarial patterns to test the robustness of both the **Base58Check BTC detector** and the **hex‑based ETH detector**.

- **Valid ETH addresses**

Three syntactically valid Ethereum addresses appear in the sample:

   - embedded inside surrounding noise
   - wrapped in brackets
   - presented in lowercase hex

These confirm that the ETH extractor:

   - correctly identifies 40‑hex‑character addresses
   - is case‑insensitive
   - extracts valid addresses even when surrounded by arbitrary characters

- **Invalid or near‑miss ETH patterns**

The fixture includes:

   - a 39‑character truncated ETH address
   - a hex‑looking string containing invalid characters (`G`)

These confirm that the ETH detector:

   - enforces strict length
   - enforces strict hex character set
   - does not extract ETH‑like noise

- **BTC Base58Check adversarial patterns**

The fixture includes:

   - two well‑known BTC‑looking addresses
      - both are **checksum‑invalid**, ensuring they must not be extracted
   - truncated Base58 strings
   - short Base58‑looking sequences

These confirm that the BTC detector:

   - performs full **Base58Check validation**
   - rejects all invalid BTC addresses
   - does not rely on regex alone
   - produces **no BTC results** for this fixture

- **Noise‑embedded patterns**

The sample includes:

   - ETH‑like garbage sequences
   - Base58‑looking noise
   - BTC‑like substrings missing final characters

These confirm that the extractor:

   - does not over‑match
   - does not reconstruct partial addresses
   - remains stable under adversarial noise

# Contract enforced

Under `analysis_level = full`, IOCX must:

- Extract:

   - **Exactly three** valid ETH addresses
      - `0x12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab`
      - `0xabcdefabcdefabcdefabcdefabcdefabcdefabcd`
      - `0x00112233445566778899aabbccddeeff00112233`

- Not extract:

   - **Any BTC addresses** (none in the fixture are checksum‑valid)
   - Any truncated or malformed ETH patterns
   - Any Base58‑looking noise
   - Any ETH‑like garbage sequences

- Maintain:

   - Deterministic output ordering
   - Stable JSON formatting
   - No false positives

This fixture verifies that the crypto extractor enforces:

   - **Base58Check** for BTC
   - **strict 40‑hex validation** for ETH
   - **no extraction of malformed or partial patterns**

# Final IOC Output (Expected)

```
crypto.btc: []
crypto.eth:
  - 0x12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab
  - 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd
  - 0x00112233445566778899aabbccddeeff00112233
```

# Conclusion

This adversarial fixture confirms that IOCX’s cryptocurrency extraction engine is:

- checksum‑aware
- strict and conservative
- resistant to noise and near‑miss patterns
- deterministic and stable
- safe for automated threat‑intelligence ingestion

The output is correct, reproducible, and fully aligned with IOCX’s design goals.
