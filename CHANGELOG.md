# **v0.7.1 — Heuristics Engine Expansion & Structural Analysis Improvements**
**Released: 2026‑05‑??**

v0.7.1 delivers a major upgrade to IOCX’s **PE heuristics engine**, **extractor correctness**, and **adversarial‑input resilience**. This release introduces six new structural heuristics, broad extractor hardening, and a significantly expanded adversarial test suite — including **full adversarial coverage for every IOC category**.

---

# **Extractor Hardening**

This release strengthens multiple IOC extractors with improved correctness, boundary handling, and adversarial‑text resilience. Updates span the **bare domain**, **strict URL**, **crypto**, and **hash** extractors, plus improved **URL normalisation**.

## **Bare Domain Extractor**

### Improvements
- Expanded **TLD allow‑list** (e.g., `.ly`, `.gg`, `.sh`, `.app`, `.dev`, `.xyz`, `.online`).
- Expanded **BAD_TLD deny‑list** to prevent file extensions and config keys from being misclassified.
- Refined **left/right boundary rules** to reduce false positives in noisy text.
- Added **punycode homoglyph detection** for IDN and mixed‑script domains.
- Improved regex clarity and stability to avoid pathological backtracking.

### Impact
- Higher recall for real‑world domains.
- Fewer false positives from filepaths and dotted log keys.
- Better homoglyph‑aware metadata.

---

## **Strict URL Extractor**

### Improvements
- Added support for `ftp`, `ftps`, and `sftp`.
- RFC‑compliant **userinfo parsing** (`user:pass@host`).
- Full **punycode** domain support.
- Improved **IPv6** handling (including zone indices).
- More robust host matching aligned with the updated domain extractor.
- Cleaner separation of path/query/fragment parsing.

### Impact
- More complete URL extraction.
- Fewer truncated or malformed URLs.
- Better handling of obfuscated or credential‑embedded URLs.

---

## **Crypto Extractor**

### Improvements
- Added **full Base58Check validation** for Bitcoin:
  - Double‑SHA256 checksum verification.
  - Version‑byte validation (`0x00`, `0x05`).
  - Rejects malformed Base58 sequences.
- Preserved Bech32/Taproot and ETH detection.

### Impact
- Dramatic reduction in Base58 false positives.
- Only cryptographically valid BTC addresses are extracted.

---

## **Hash Extractor**

### Improvements
- Increased short‑hex minimum length from **8 → 10** characters.
- Strict MD5/SHA1/SHA256/SHA512 detection unchanged.

### Impact
- Fewer false positives from small hex tokens.
- Behaviour remains aligned with adversarial fixtures.

---

## **URL Normalisation**

- `normalise_url()` now wraps `urlparse()` in safe error handling.
- Malformed URLs return `None` instead of raising.

### Impact
- More robust behaviour on adversarial URL input.
- Prevents crashes during bulk extraction.

---

# **Heuristics Engine Expansion (PE Structural Analysis)**

To support the expanded adversarial PE corpus, v0.7.1 introduces **six new deterministic heuristics** for detecting malformed or inconsistent PE structures:

- **Section overlap detection**
  `_analyse_section_overlap`
- **Section alignment validation**
  `_analyse_section_alignment`
- **Optional‑header consistency checks**
  `_analyse_optional_header_consistency`
- **Entrypoint → section mapping validation**
  `_analyse_entrypoint_mapping`
- **Data‑directory anomaly detection**
  `_analyse_data_directory_anomalies`
- **Import‑directory validity checks**
  `_analyse_import_directory_validity`

### Impact
- Clearer, reason‑coded anomaly reporting.
- No false positives on benign binaries.
- Deterministic behaviour across malformed PE structures.

---

# **Added**

### **1. Full adversarial fixtures for *all* IOC categories**
New adversarial string corpora added for:

- **crypto wallets** (BTC/ETH, reversed, embedded, noisy, base58‑adjacent)
- **domains** (Unicode homoglyphs, mixed‑script lookalikes)
- **URLs** (broken schemes, nested encodings, truncated fragments)
- **IPs** (malformed IPv4/IPv6, concatenated segments, invalid scopes)
- **filepaths** (MAX_PATH‑breaking Windows paths, malformed UNC prefixes)
- **hashes** (near‑miss hex sequences, truncated digests)
- **base64** (invalid padding, embedded noise, extremely long runs)
- **emails** (Unicode variants, malformed local parts)

Each fixture includes a deterministic snapshot.

### **2. Expanded adversarial PE corpus**
Fixtures include:

- broken RVAs
- overlapping/misaligned sections
- corrupted data directories
- malformed import tables
- invalid optional headers (PE32 & PE32+)
- truncated Rich headers
- packed‑lookalike binaries
- franken‑PE hybrids

### **3. Heuristics engine upgrades**
- New structural heuristics (see above)
- Unified internal analysis structure (`sections` + `data_directories`)
- Deterministic, JSON‑safe anomaly reporting

---

# **Fixed**

- Improved stability when parsing malformed or adversarial PE files.
- More robust handling of malformed URLs during normalisation.

---

# **Notes**

- Updated snapshot for `heuristic_rich.full.exe` to reflect new heuristics.
- Previous snapshot predated directory‑range and RVA‑validation logic.

---
