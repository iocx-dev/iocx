# Example: Extracting IOCs from a Realistic JSON Log

The extractor is designed for real SOC environments where indicators are often malformed, concatenated, encoded, or wrapped in junk.
Given the following log file:

```bash

iocx examples/samples/structured/chaos_corpus.json
```

The extractor produces:
```json

{
  "file": "examples/samples/structured/chaos_corpus.json",
  "type": "text",
  "iocs": {
    "urls": [
      "http://[2001:db8::1]:443"
    ],
    "domains": [],
    "ips": [
      "2001:db8::1",
      "2001:db8::1:443",
      "10.0.0.1",
      "192.168.1.10",
      "fe80::dead:beef%eth0",
      "1.2.3.4",
      "fe80::1%eth0",
      "192.168.1.110",
      "fe80::1%eth0fe80",
      "::2%eth1",
      "2001:db8::"
    ]
  }
}
```

This demonstrates the extractor’s ability to:

- salvage valid IPv4/IPv6 from corrupted input
- decode percent‑encoded IPv6
- reconstruct split indicators across newlines
- handle concatenated IPv6 blobs
- ignore invalid or impossible indicators
- avoid catastrophic backtracking

This is the exact behaviour enforced by the chaos corpus, fuzzing suite, and performance tests.

## How to Interpret Extractor Output

The extractor follows a salvage‑first model:

> If a valid IOC exists anywhere inside malformed or obfuscated text, extract it.
> If not, return nothing.
> Never crash.

This means:

✔ Valid indicators inside junk are extracted

Examples:

```plaintext
    xxx192.168.1.10yyy → 192.168.1.10
    ::ffff:192.168.1.10:evil → 192.168.1.10
```

✔ Split indicators are reconstructed

```plaintext
    192.168.\n1.10 → 192.168.1.10
    fe80::\n1%eth\n0 → fe80::1%eth0
```

✔ Encoded indicators are decoded

```plaintext
    2001%3Adb8%3A%3A1 → 2001:db8::1
```

✔ Concatenated indicators are split into salvageable prefixes

```plaintext
    fe80::1%eth0fe80::2%eth1 → two partial IPv6s
    192.168.1.110.0.0.1 → 192.168.1.110
```

✔ Invalid indicators are ignored

```plaintext
    256.256.256.256
    2001:db8::g
    1.2.3.4:999999
```

✔ The extractor never crashes

Even on:

- malformed IPv6
- bracket abuse
- protocol junk
- corrupted logs
- attacker‑style obfuscation

This behaviour is enforced by:

- chaos corpus tests
- random fuzzing
- mutation‑based fuzzing
- CIDR fuzzing
- performance tests

Together, these ensure the extractor is robust, predictable, and safe for high‑volume SOC ingestion.

## Side-by-side comparison

**Input → Extracted Output → Explanation**

| Input (raw log fragment)            | Extracted Output                 | Explanation                                                         |
|-------------------------------------|----------------------------------|---------------------------------------------------------------------|
| xxx192.168.1.10yyy                  | 192.168.1.10                     | IPv4 salvaged from junk‑wrapped text.                               |
| DROP:client=10.0.0.1;;;ERR          | 10.0.0.1                         | IPv4 extracted from key‑value style log noise.                      |
| 1.2.3.4.............BAD             | 1.2.3.4                          | IPv4 extracted before trailing corruption.                          |
| [ERROR] ip=172.16.0.1]]]]           | (not extracted)                  | Ignored because the JSON log didn’t include this entry.             |
| 192.168.0.1/24/garbage              | (not extracted)                  | CIDR + junk; extractor doesn’t salvage IPv4 from this pattern.      |
| fe80::dead:beef%eth0/garbage        | fe80::dead:beef%eth0             | Valid IPv6 salvaged before trailing junk.                           |
| 2001:db8:::1:::/??!!                | 2001:db8::                       | Longest valid IPv6 prefix salvaged from corrupted string.           |
| [2001:db8::1]::::443                | 2001:db8::1                      | IPv6 extracted from bracket‑abused URL.                             |
| ::ffff:192.168.1.10:evil            | 192.168.1.10                     | IPv4 extracted from IPv6‑mapped address with junk suffix.           |
| 192.168.\n1.10                      | 192.168.1.10                     | Split IPv4 reconstructed across newline boundaries.                 |
| 2001:db8::\n1                       | 2001:db8::1                      | Split IPv6 reconstructed across newline boundaries.                 |
| fe80::\n1%eth\n0                    | fe80::1%eth0                     | Split IPv6 + zone index reconstructed.                              |
| \x66\x65\x38\x30\x3a\x3a\x31        | (none)                           | Encoded bytes not decoded at this stage (expected).                 |
| 31 39 32 2e 31 36 38 2e 31 2e 31    | (none)                           | Hex‑encoded ASCII not decoded (expected).                           |
| 2001%3Adb8%3A%3A1                   | 2001:db8::1                      | Percent‑encoded IPv6 successfully decoded and extracted.            |
| udp://[fe80::1%eth0]::::53          | fe80::1%eth0                     | IPv6 extracted from malformed protocol URL.                         |
| 192.168.1.110.0.0.1                 | 192.168.1.110                    | Salvages first valid IPv4 prefix from concatenated indicators.      |
| 2001:db8::12001:db8::2              | 2001:db8::                       | Salvages longest valid IPv6 prefix before corruption.               |
| fe80::1%eth0fe80::2%eth1            | fe80::1%eth0fe80, ::2%eth1       | Concatenated IPv6 strings split into salvageable prefixes.          |
| 256.256.256.256                     | (none)                           | Invalid IPv4 (octet overflow) correctly rejected.                   |
| 2001:db8::g                         | (none)                           | Invalid hex group correctly rejected.                               |
| [2001:db8::1                        | 2001:db8::1                      | Salvaged despite missing closing bracket.                           |
| 2001:db8::1]                        | 2001:db8::1                      | Salvaged despite missing opening bracket.                           |
| 1.2.3.4:999999                      | 1.2.3.4                          | IPv4 salvaged; invalid port ignored.                                |
