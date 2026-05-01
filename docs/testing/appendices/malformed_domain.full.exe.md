# Appendix 3.24 — Malformed Domain Adversarial Specification

**File:** `malformed_domain.full.exe`
**Layer: 3** — `Adversarial`

# Purpose

This adversarial fixture validates IOCX’s domain extraction pipeline under **malformed, obfuscated, and misleading conditions**. It ensures that the domain detector:

- extracts only syntactically valid domain names
- rejects split, reversed, or partial domains
- ignores structured‑log lookalikes and file‑extension strings
- handles punycode correctly
- does not extract domains from obfuscation patterns unless explicitly deobfuscated
- remains deterministic and false‑positive‑resistant

The fixture is designed to confirm that IOCX’s domain extractor is strict, conservative, and adversarially hardened.

# Behaviours Exercised

This sample mixes valid domains, invalid fragments, reversed sequences, and obfuscation‑like patterns to test the robustness of the domain detector.

## Valid literal domains

Eight valid domains are embedded as literal strings:

- `example.com`
- `sub.domain.co.uk`
- `evil.dev`
- `xn--e1afmkfd.xn--p1ai` (punycode)
- `test.online`
- `foo.xyz`
- `api.example.com`
- `sub.example.io`

These confirm that the extractor:

- correctly handles multi‑label domains
- supports punycode
- supports multi‑level subdomains
- preserves case‑insensitive matching
- extracts domains even when surrounded by arbitrary characters

## Split and reversed domains (should NOT be extracted)

The fixture includes:

- `example.co` + `m` split across bytes
- reversed `moc.elpmaxe`
- reversed punycode `iap.n--xn`

These confirm that the extractor:

- does not reconstruct split domains
- does not reverse strings
- does not extract invalid punycode sequences
- does not match domain‑like noise

## BAD_TLDS and file‑extension lookalikes

The sample includes:

- `config.json`
- `script.js`
- `payload.exe`

These confirm that the extractor:

- does not treat file names as domains
- enforces a valid TLD list
- rejects common structured‑log tokens

## Structured log lookalikes

Examples include:

- `network.connection`
- `auth.failure`
- `log.corruption`

These confirm that the extractor:

- does not treat dotted log keys as domains
- enforces hostname syntax rules
- avoids false positives in telemetry‑style text

## Obfuscation‑like domain patterns

Examples:

- `evil[.dev`
- `api[.example[.com`

These confirm that:

- obfuscation markers (`[.]`) are not interpreted as dots
- no deobfuscation occurs at this layer
- the extractor does not reconstruct obfuscated domains

## Random noise

Ensures extractor stability under arbitrary byte sequences.

# Contract Enforced

Under `analysis_level = full`, IOCX must:

Extract exactly the following domains:

- `example.com`
- `sub.domain.co.uk`
- `evil.dev`
- `xn--e1afmkfd.xn--p1ai`
- `test.online`
- `foo.xyz`
- `api.example.com`
- `sub.example.io`

Not extract:

- split domains
- reversed domains
- reversed punycode
- file‑extension lookalikes
- structured‑log keys
- obfuscation‑like patterns (`evil[.dev`)
- any domain not explicitly present as a valid literal

# Maintain:

- deterministic ordering
- stable JSON formatting
- zero false positives
- strict TLD validation
- correct punycode handling

This fixture verifies that the domain extractor is strict, non‑reconstructive, and resistant to adversarial noise.

# Final IOC Output (Expected)
```
domains:
  - example.com
  - sub.domain.co.uk
  - evil.dev
  - xn--e1afmkfd.xn--p1ai
  - test.online
  - foo.xyz
  - api.example.com
  - sub.example.io
```

No URLs, IPs, hashes, emails, filepaths, or crypto addresses should be extracted.

# Conclusion

This adversarial fixture confirms that IOCX’s domain extraction engine is:

- conservative and false‑positive‑resistant
- robust against split, reversed, and obfuscated patterns
- strict about TLD and hostname syntax
- punycode‑aware
- deterministic and stable under adversarial input

The output is correct, reproducible, and fully aligned with IOCX’s design goals.
