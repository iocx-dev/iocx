# Appendix 3.21 — Email Strings Adversarial Specification

- **File:** `emails_strings_adversarial.full.bin`
- **Layer: 3** — `Adversarial`

# Purpose

This fixture verifies IOCX’s behaviour when extracting **email‑like strings from noisy, adversarial, or malformed text**. The email detector intentionally uses a simple, permissive, industry‑standard regex that prioritises high recall over strict RFC compliance. This is the same approach used across DFIR tooling, SIEM field extractors, and IOC scrapers.

The goal is to ensure that IOCX:

- extracts syntactically valid email‑like tokens
- extracts emails embedded in URLs
- extracts emails embedded inside larger tokens (expected behaviour)
- rejects clearly malformed or incomplete addresses
- does not attempt to reconstruct split emails
- does not confuse dotted identifiers or garbage strings with emails

This appendix documents the expected behaviour for each case.

# Expected Matches

The following lines contain syntactically valid email‑like strings and must be extracted:

- `contact@example.com`
- `first.last@sub.domain.co.uk`
- `user+tag@my-server.example`
- `admin@example.org` (*from mailto:*)
- Embedded email inside a larger token:
   - `token=abc123user@example.comxyz`

# Expected Non‑Matches

The following lines must not produce email matches:

- Underscore‑bounded email (word boundary fails):
   - `xxx_support@company.com_yyy`
      Underscores break `\b` boundaries, so this does not match.
- Missing or invalid TLD:
   - `broken@localhost`
   - `user@domain`
   - `bad@domain.c`
   - `weird@domain.123`

These fail the \.[A-Za-z]{2,} requirement.

- Split emails
   - `split@exa`
   - `mple.com`
   The extractor does not reconstruct across newlines.
- Dotted keys
   - `auth.failure.reason`
   - `network.connection.error`
   No @ → no match.
- Garbage with @ signs
   - `@@@@notanemail@@@@`
   - `user@@example.com`
   Malformed → no match.

# Interaction With Domain Extractor

This fixture may also produce domain matches such as:

- `mple.com`

from the split email fragment.

This is correct behaviour.

The email detector does not suppress domain extraction, and the domain detector does not infer email context.

# Summary

This adversarial fixture confirms that IOCX’s email detector:

- uses a simple, permissive, DFIR‑grade regex
- extracts valid and embedded email‑like strings
- rejects malformed, incomplete, or split addresses
- behaves predictably in noisy or adversarial text
- does not attempt over‑strict validation or reconstruction

This behaviour is intentional and aligns with IOCX’s design philosophy:

> extract what looks like an email, avoid over‑engineering, and keep the signal high.
