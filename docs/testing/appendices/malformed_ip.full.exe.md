# Appendix 3.25 — Malformed IP Adversarial Specification

- **File:** `malformed_ip.full.exe`
- **Layer: 3** — `Adversarial`

# Purpose

This adversarial fixture validates IOCX’s **IPv4 and IPv6 extraction pipeline** under malformed, concatenated, obfuscated, and misleading conditions. It ensures that the IP detector:

- extracts only syntactically valid IPv4, IPv6, and CIDR notations
- rejects malformed IPv6 sequences
- does not reconstruct split IPs
- performs salvage extraction on concatenated IPv4 sequences
- correctly handles IPv6 zone indices
- extracts bracketed IPv6 even outside URL contexts
- avoids false positives from mixed garbage or embedded domains

The fixture is designed to confirm that IOCX’s IP extractor is **strict, salvage‑aware, and adversarially hardened.**

# Behaviours Exercised

This sample mixes valid literal IPs, malformed fragments, concatenated sequences, and IPv6 edge cases to test the robustness of the IP detector.

## Valid literal IPv4, IPv6, and CIDR

The binary embeds twelve literal IP strings:

### IPv4:

- `1.2.3.4`
- `10.0.0.1`
- `192.168.1.10`
- `8.8.8.8`

### IPv4 CIDR:

- `10.0.0.0/8`
- `192.168.0.0/16`

### IPv6 + CIDR:

- `2001:db8::/32`
- `2001:db8::1`

### IPv6 link‑local + zone index:

- `fe80::1`
- `fe80::dead:beef`
- `fe80::1%eth0`

These confirm that the extractor:

- supports IPv4, IPv6, and CIDR
- handles IPv6 compression (`::`)
- handles IPv6 zone indices (`%eth0`)
- extracts bracketed IPv6 (`[2001:db8::1]`) as plain IPs

## Split IPv4 and IPv6 (should NOT be reconstructed)

Examples include:

- `192.168. + 1\n10`
- `2001:db8:: + \n1`

These confirm that the extractor:

- does not join split sequences
- does not reconstruct across newlines
- does not attempt to “fix” broken IPs

## Concatenated IPv4 salvage behaviour

The fixture includes:

```
192.168.1.110.0.0.1
```

IOCX correctly salvages the **valid trailing IPv4**:

```
168.1.110.0
```

This confirms that the extractor:

- scans inside concatenated garbage
- extracts valid IPv4 substrings
- does not require whitespace or delimiters

## Malformed IPv6 (should NOT be extracted)

Examples include:

- `2001:db8::g`
- `2001:db8::1evil.dev`

These confirm that the extractor:

- rejects IPv6 containing invalid hex characters
- stops extraction before domain suffixes
- does not salvage partial IPv6 sequences

## Bracketed IPv6 outside URL context

The fixture includes:

```
[2001:db8::1]
```

IOCX correctly extracts:

```
2001:db8::1
```

This confirms that:

- IPv6 extraction is not tied to URL parsing
- brackets do not suppress IP detection

## Domain embedded in IP‑like garbage

The fixture includes:

```
2001:db8::1evil.dev
```

IOCX correctly extracts:

- domain: `1evil.dev`
- no IPv6 (invalid)

This confirms that:

- domain extraction and IP extraction remain independent
- invalid IPv6 does not suppress domain detection

# Contract Enforced

Under `analysis_level = full`, IOCX must:

## Extract exactly the following IPs:

- `1.2.3.4`
- `10.0.0.1`
- `192.168.1.10`
- `8.8.8.8`
- `10.0.0.0/8`
- `192.168.0.0/16`
- `2001:db8::/32`
- `2001:db8::1`
- `fe80::1`
- `fe80::dead:beef`
- `fe80::1%eth0`
- `168.1.110.0` (*salvaged from concatenated IPv4*)

## Extract exactly the following domains:

- `1evil.dev` (*from mixed garbage*)

## Not extract:

- split IPv4 or IPv6 fragments
- malformed IPv6 (`::g`, `::1evil.dev`)
- any partial or truncated IPs
- any reconstructed IPs
- any IPv6 zone‑index addresses not present in the binary

## Maintain:

- deterministic ordering
- stable JSON formatting
- strict IPv6 validation
- salvage behaviour for IPv4 only
- no false positives

This fixture verifies that the IP extractor is **strict for IPv6, salvage‑aware for IPv4, and non‑reconstructive**.

# Final IOC Output (Expected)

```
ips:
  - 1.2.3.4
  - 10.0.0.1
  - 192.168.1.10
  - 8.8.8.8
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 2001:db8::/32
  - 2001:db8::1
  - fe80::1
  - fe80::dead:beef
  - fe80::1%eth0
  - 168.1.110.0

domains:
  - 1evil.dev
```

No URLs, hashes, emails, filepaths, or crypto addresses should be extracted.

# Conclusion

This adversarial fixture confirms that IOCX’s IP extraction engine is:

- strict about IPv6 syntax
- salvage‑capable for IPv4
- resistant to split, reversed, and malformed sequences
- robust against embedded domains and mixed garbage
- deterministic and stable under adversarial input

The output is correct, reproducible, and fully aligned with IOCX’s design goals.
