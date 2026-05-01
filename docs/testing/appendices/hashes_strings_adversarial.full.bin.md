# Appendix 3.22 — Hash Strings Adversarial Specification

- **File:** `hashes_strings_adversarial.full.bin`
- **Layer: 3** — `Adversarial`

# Purpose

This fixture validates IOCX’s hash extractor against **adversarial, ambiguous, and intentionally misleading hex‑like strings**.

The extractor uses a hybrid model:

## 1. Strict hash detection

Recognises canonical cryptographic hash lengths:

- MD5 -> 32 hex
- SHA1 -> 40 hex
- SHA256 -> 64 hex
- SHA512 -> 128 hex

## 2. Heuristic short‑hex detection

Extracts any standalone hex‑only token of length ≥10, even if it is not a known hash length.

This captures:

- partial hashes
- truncated hashes
- malware IDs
- obfuscation keys
- GUID segments
- split‑line fragments

This behaviour is intentional and part of IOCX’s design philosophy.

# Expected Matches

The extractor must identify the following categories of hex strings:

## Valid cryptographic hashes

- `d41d8cd98f00b204e9800998ecf8427e` (MD5)
- `da39a3ee5e6b4b0d3255bfef95601890afd80709` (SHA1)
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (SHA256)
- `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` (SHA512)
- `D41D8CD98F00B204E9800998ECF8427E` (mixed‑case MD5)

## Valid‑length substrings extracted from split hashes

The split SHA‑256:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4
649b934ca495991b7852b855
```

produces:

- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4` (40 hex → valid SHA1)
- `649b934ca495991b7852b855` (24 hex → heuristic short‑hex)

The extractor does not attempt to reconstruct the original SHA‑256.

It extracts any valid standalone hex token.

## Valid‑length segments inside GUID‑like strings

From:

```
550e8400-e29b-41d4-a716-446655440000
```

the final segment:

`446655440000` (12 hex → heuristic short‑hex)

is extracted.

This is expected: GUID segments are treated as standalone hex tokens.

# Expected Non‑Matches

The extractor must not match:

## Too‑short hex strings:

- `deadbeef`
- `cafebabe`

(<10 hex chars)

## Hex strings of invalid lengths:

- 41‑hex
- 44‑hex

(or any length not ≥10 and not a strict hash length)

## Embedded hashes inside larger tokens

`xxxd41d8cd98f00b204e9800998ecf8427eyyy`

(no standalone boundaries)

## Hex dumps with spaces or formatting

`00000000 41 41 41 41 42 42 42 42 |AAAA BBBB|`

(non‑contiguous hex → rejected)

# Design Philosophy

The hash extractor intentionally:

- does not validate algorithm semantics
- does not require known hash prefixes
- does not reconstruct split hashes
- extracts any standalone hex token ≥10 chars
- extracts valid‑length substrings inside larger structures (e.g., GUIDs)
- extracts strict hash lengths even when embedded in multi‑line data
- rejects spaced, formatted, or non‑contiguous hex

This approach ensures:

- high recall
- predictable behaviour
- robustness in adversarial inputs
- compatibility with real‑world DFIR data
- alignment with the contract suite
