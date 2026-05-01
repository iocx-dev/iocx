# Appendix 3.18 — Homoglyph & IDN Domains Adversarial Specification

- **File:** `homoglyph_domains_adversarial.full.bin`
- **Layer:** 3 — `Adversarial`

## Purpose

This fixture validates IOCX’s **bare domain extractor** when confronted with:

- normal ASCII domains
- Unicode homoglyph lookalikes
- mixed‑script domain‑like strings
- punycode domains (valid, invalid, ASCII‑only, and Unicode‑decoding)
- Unicode noise surrounding domain‑like text

The goal is to ensure that IOCX:

- extracts **only ASCII domain tokens** from the raw text
- correctly identifies punycode domains
- correctly determines whether punycode decodes to Unicode
- exposes the decoded Unicode form (if any)
- identifies whether the decoded Unicode contains confusable characters
- identifies the script(s) used in the decoded Unicode domain

This appendix documents the expected behaviour of the extractor and the metadata fields it emits.

## Input construction

The generator writes:

1. A set of normal ASCII domains
2. Unicode homoglyph substitutions (Cyrillic, Greek)
3. Mixed‑script domain‑like strings
4. Punycode‑like ASCII domains
5. Unicode noise around domain‑like text

Representative inputs:

```
paypal.com google.com microsoft.com example.org
раураl.com
gоogle.com
microsоft.cоm
xn--paypaI-l2c.com
xn--g00gle-9za.com
✪раураl.com✪
❖gοοgle.com❖
```

## Expected matches

The extractor produces the following `domains` array:

```json
[
  "paypal.com",
  "google.com",
  "microsoft.com",
  "example.org",
  "l.com",
  "ogle.com",
  "xn--paypai-l2c.com",
  "xn--g00gle-9za.com",
  "gle.com"
]
```

This reflects the extractor’s **ASCII‑only matching rule**:
Unicode homoglyphs are ignored, and only ASCII substrings that match the domain regex are extracted.

## Metadata expectations

Each extracted domain includes:

```json
{
  "punycode": <bool>,
  "punycode_decodes_to_unicode": <bool>,
  "decoded_unicode": <string|null>,
  "contains_confusables": <bool>,
  "script": "Latin|Cyrillic|Greek|Mixed|Other"
}
```

### 1. Normal ASCII domains

Example: `paypal.com`

- `punycode`: false
- `punycode_decodes_to_unicode`: false
- `decoded_unicode`: null
- `contains_confusables`: false
- `script`: "Latin"

### 2. Homoglyph domains (ASCII suffix extraction)

Input: `раураl.com` (Cyrillic letters)

Extracted: `l.com`

Metadata:

- `punycode`: false
- `punycode_decodes_to_unicode`: false
- `decoded_unicode`: null
- `contains_confusables`: false
- `script`: "Latin"

The Unicode homoglyphs are **not** part of the extracted domain, so no Unicode metadata applies.

### 3. Punycode domains (ASCII‑only decoding)

Input: `xn--g00gle-9za.com`

Decoded: `g00gle-9za.com` (ASCII only)

Metadata:

- `punycode`: true
- `punycode_decodes_to_unicode`: false
- `decoded_unicode`: "g00gle-9za.com"
- `contains_confusables`: false
- `script`: "Latin"

### 4. Punycode domains (Unicode‑decoding)

Input: `xn--e1awd7f.com`

Decoded: `аррӏе.com` (Cyrillic homoglyph attack)

Metadata:

- `punycode`: true
- `punycode_decodes_to_unicode`: true
- `decoded_unicode`: "аррӏе.com"
- `contains_confusables`: true
- `script`: "Cyrillic"

### 5. Unicode noise around domains

Input: `✪раураl.com✪`

Extracted: `l.com`

Metadata is identical to ASCII domains, because the Unicode characters are not part of the extracted token.

## Expected non‑matches

The extractor must **not** treat the following as domains:

- full Unicode homoglyph domains (`раураl.com`)
- mixed‑script domains (`microsоft.cоm`)
- Unicode‑only domain‑like tokens
- invalid punycode labels
- domain‑like substrings embedded inside Unicode sequences

Only ASCII substrings that match the domain regex are extracted.

## Design philosophy

This fixture encodes the following expectations:

### 1. ASCII‑only extraction
The extractor matches only ASCII domain tokens.
Unicode homoglyphs are ignored at the extraction stage.

### 2. Punycode is treated syntactically
Any `xn--` label is extracted if it matches the domain regex.

### 3. Unicode decoding happens **after** extraction
Decoded Unicode is metadata only — it does not affect extraction.

### 4. Confusable detection is metadata‑only
If the decoded Unicode contains Cyrillic or Greek characters visually similar to Latin,
`contains_confusables` is set to `true`.

### 5. Script classification
The `script` field identifies the Unicode script(s) used in the decoded domain.

### 6. Invalid punycode is safely ignored
If decoding fails, the extractor:

- keeps the ASCII punycode label
- sets `decoded_unicode = null`
- sets `punycode_decodes_to_unicode = false`

## Summary

`homoglyph_domains_adversarial.full.bin` validates that IOCX:

- extracts only ASCII domain tokens
- correctly identifies punycode domains
- correctly determines whether punycode decodes to Unicode
- exposes the decoded Unicode form
- detects confusable Unicode characters
- identifies the Unicode script used

This ensures IOCX is robust against homoglyph attacks, IDN spoofing, mixed‑script deception, and Unicode noise — while maintaining a strict, predictable ASCII extraction model.
