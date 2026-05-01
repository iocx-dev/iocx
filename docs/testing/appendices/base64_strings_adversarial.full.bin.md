# Appendix 3.23 — Base64 Strings Adversarial Specification

**File:** `base64_strings_adversarial.full.bin`
**Layer:** 3 — `Adversarial`

## Purpose

This adversarial fixture validates IOCX’s **base64 extraction pipeline** under noisy, misleading, and boundary‑challenging conditions. It ensures that the extractor:

- extracts only standalone, decodable, ASCII‑dominant base64 tokens
- rejects short, random, numeric‑only, or binary‑like decodes
- correctly handles URL‑safe and unpadded base64
- enforces strict token boundaries (no embedded matches)
- remains deterministic and resistant to false positives

The fixture confirms that IOCX’s base64 extractor is **strict, predictable, and adversarially hardened**.

## Behaviours Exercised

This sample mixes valid base64, near‑misses, binary‑like decodes, and boundary edge cases to test the robustness of the detector.

### Valid standalone base64 (ASCII decodes)

The fixture includes base64 tokens that decode to human‑readable ASCII and appear with clear boundaries:

- `QmFzZTY0IGlzIG5vdCBqdXN0IGZvciBiaW5hcnk=`
- `ZXhhbXBsZS11cmwtc2FmZS1iYXNlNjQ`
- `QUJDREVGRw==` (short, but ASCII‑only → accepted)

These confirm that IOCX:

- decodes safely
- accepts ASCII‑dominant output
- preserves the original encoded value
- requires clear token boundaries

### URL‑safe, unpadded base64

The fixture includes:

- `ZXhhbXBsZS11cmwtc2FmZS1iYXNlNjQ`

This confirms that IOCX:

- accepts URL‑safe base64 (`-` and `_`)
- handles missing padding
- decodes using URL‑safe semantics

### Short base64‑like tokens

Examples:

- `QUJDREVGRw==` --> `"ABCDEFG"` --> accepted (ASCII‑only)
- `YWJjZA==` --> `"abcd"` --> rejected (too short, low signal)

These confirm that IOCX:

- accepts short ASCII‑only decodes
- rejects short low‑signal decodes
- avoids over‑matching trivial noise

### Binary‑like decodes (rejected)

Examples:

- `/////w8PDw8PDw8PDw8PDw8PDw8PDw8PDw8=`
- `AAAAAAAA8P///wD////A////AP///wD///8=`

These confirm that IOCX:

- rejects decodes dominated by non‑printable bytes
- avoids surfacing encrypted or random binary blobs

### Numeric‑only decodes (rejected)

Example:

- `MTIzNDU2Nzg5MDA5ODc2NTQzMjEw` --> `123456789009876543210`

This confirms that IOCX:

- rejects purely numeric decodes
- avoids meaningless or low‑entropy output

### Boundary‑sensitive matching

Example:

- `prefix-SGVsbG8sIFdvcmxkIQ==-suffix`
- `xxxxVXNlci1hZ2VudDogQmFzZTY0LXRlc3Q=yyyy`
- `wrapped_token=xxxSGVsbG8sIFdvcmxkIQ==yyy`

These confirm that IOCX:

- does not match base64 embedded inside larger tokens
- requires clear boundaries before and after the token
- avoids false positives in structured text

### Noise using the base64 alphabet (rejected)

Example:

- `++++////++++////++++////`

This confirms that IOCX:

- does not rely on regex alone
- requires successful decoding + text‑likeness
- rejects alphabet‑compatible noise

### UTF‑16LE‑like base64 (rejected)

The fixture includes:

- `dXRmMTYtTEU6AEgAZQBsAGwAbwAhAA==`

This confirms that IOCX:

- no longer treats UTF‑16LE as text
- requires ASCII‑dominant decodes
- avoids null‑byte‑heavy output

## Contract Enforced

Under `analysis_level = full`, IOCX must:

### Extract exactly these base64 tokens:

- `QmFzZTY0IGlzIG5vdCBqdXN0IGZvciBiaW5hcnk=`
- `ZXhhbXBsZS11cmwtc2FmZS1iYXNlNjQ`
- `QUJDREVGRw==`

Each detection must include:

- the original encoded value as `value`
- `category = "base64"`
- `metadata.decoded` containing the decoded ASCII text

### Must NOT extract:

- short low‑signal decodes (YWJjZA==)
- binary‑like decodes
- numeric‑only decodes
- embedded base64 inside larger tokens
- random alphabet‑compatible noise
- UTF‑16LE‑like decodes

### Must maintain:

- deterministic ordering
- strict boundary enforcement
- safe decoding
- zero false positives

## Final IOC Output (Expected)

```json
    "base64": [
      "QmFzZTY0IGlzIG5vdCBqdXN0IGZvciBiaW5hcnk=",
      "ZXhhbXBsZS11cmwtc2FmZS1iYXNlNjQ",
      "QUJDREVGRw=="
    ]
```
No other IOC categories should produce matches.

# Conclusion

This adversarial fixture confirms that IOCX’s base64 extractor is:

- strict and ASCII‑focused
- resistant to noise, binary blobs, and embedded tokens
- robust against misleading or borderline input
- deterministic and safe under adversarial conditions

It extracts only meaningful, standalone, text‑like base64 IOCs — fully aligned with the engine’s design goals.
