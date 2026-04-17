# Appendix 3.3 — Adversarial PE (string obfuscation) Specification

- **File:** string_obfuscation_tricks.bin
- **Layer: 3** Adversarial PE (string obfuscation)

# Purpose:

- Validate IOC extraction from obfuscated and reversed strings.
- Validate IP extraction.
- Validate anti-debug heuristic detection.
- Ensure custom low-entropy section is handled correctly.

# Expected Characteristics:

- Contains a custom section named `.obfs`.
- `.obfs` section entropy < 1.0.
- Extracted URLs include:
    - http://literal-ioc.test/path
    - http://example.com/pathmoc.elpmaxh
    - http://bad.test
- Extracted IP: 198.51.100.42
- Anti-debug heuristics for:
    - OutputDebugStringA
    - IsDebuggerPresent
    - QueryPerformanceCounter
- Rich header must be present and fully hex-encoded.
