# Appendix 3.27 — Franken URL / Domain / IP Adversarial Specification

**Fixture:** `franken_url_domain_ip.full.exe`
**Layer: 3** — `Adversarial`

# Purpose

Validate IOCX’s ability to **extract URLs, bare domains, and IP addresses from heavily fragmented, reversed, malformed, or obfuscated content embedded inside a PE file’s `.obfs` section.**

The adversarial payload mixes:

- split URLs
- reversed URLs
- malformed IPv6 hosts
- bracket‑broken hosts
- hxxp + `[.]` obfuscation
- embedded domains inside query parameters
- IPv4 and IPv6 fragments
- concatenated IPs
- structured‑log lookalikes
- BAD_TLD collisions
- deobfuscation‑style domain fragments

The goal is to ensure IOCX extracts **only valid IOCs**, ignoring noise, broken fragments, and obfuscation tricks.

## **1. Adversarial Input Construction**

The `.obfs` section contains byte‑level adversarial sequences such as:

- Split URL fragments like `"http://example.com/path"`
- Malformed IPv6 hosts such as `"[2001:db8::g]:443"`
- Broken bracketed hosts like `"[::::]/bad"`
- Reversed URL sequences such as `"moc.live//:ptth"`
- Obfuscated domains like `"evil[.dev"` and `"api[.example[.com"`
- Split IPv4 sequences like `"192.168.\n110"`
- Split IPv6 sequences like `"2001:db8::\n1"`
- Concatenated IPv4 `"192.168.1.110.0.0.1"`
- Malformed IPv6 `"2001:db8::g"`
- Mixed IPv6 + domain `"2001:db8::1evil.dev"`
- Bracketed IPv6 `"[2001:db8::1]"`

These are intentionally malformed to ensure the extractor does not produce false positives.

Literal strings embedded in the PE (via `MessageBoxA`) provide the **ground‑truth IOCs** that *must* be extracted.

## **2. Expected URL Extractions**

The extractor **must** return exactly the following URLs:

1. `http://example.com`
2. `https://sub.example.co.uk/path?x=1#frag`
3. `sftp://files.example.com/home`
4. `https://[2001:db8::1]/c2`
5. `ftps://secure.example.org/download`
6. `http://gateway.local/redirect?target=example.com`
7. `https://156.65.42.8/access.php`

All other URL‑like fragments in the `.obfs` section are malformed and **must not** be extracted.

## **3. Expected Domain Extractions**

The extractor **must** return exactly the following domains:

1. `sub.domain.co.uk`
2. `evil.dev`
3. `xn--e1afmkfd.xn--p1ai`
4. `test.online`
5. `foo.xyz`
6. `api.example.com`
7. `sub.example.io`
8. `1evil.dev`

The following **must not** be extracted:

- reversed domains (`moc.elpmax`)
- BAD_TLDs (`config.json`, `payload.exe`)
- structured log keys (`network.connection`, `auth.failure`)
- bracket‑obfuscated domains (`evil[.dev`, `api[.example[.com`)
- domain‑like fragments inside malformed URLs

## **4. Expected IP Extractions**

The extractor **must** return exactly the following IPs:

### IPv4
- `1.2.3.4`
- `10.0.0.1`
- `192.168.1.10`
- `8.8.8.8`
- `10.0.0.0/8`
- `192.168.0.0/16`
- `168.1.110.0`

### IPv6
- `2001:db8::/32`
- `2001:db8::1`
- `fe80::1`
- `fe80::dead:beef`
- `fe80::1%eth0`
- `::2%eth1`

The following **must not** be extracted:

- split IPv4 (`192.168.\n110`)
- split IPv6 (`2001:db8::\n1`)
- malformed IPv6 (`2001:db8::g`)
- mixed IPv6 + domain (`2001:db8::1evil.dev`)
- bracketed IPv6 without URL context (`[2001:db8::1]`)

## **5. Extraction Guarantees**

This adversarial fixture asserts the following guarantees:

### **URL Extraction**
- Only syntactically valid URLs are extracted.
- Reversed, split, malformed, or bracket‑broken URLs are ignored.
- IPv6 URLs must be extracted only when properly bracketed.

### **Domain Extraction**
- Only ASCII domains matching the allow‑list TLDs are extracted.
- BAD_TLDs, structured‑log keys, and obfuscated domains are ignored.
- Punycode domains are extracted and decoded for metadata.

### **IP Extraction**
- IPv4 and IPv6 extraction must be strict and RFC‑aware.
- Split or malformed addresses must not be extracted.
- Zone‑index IPv6 (`%eth0`) must be preserved.

## **6. Summary**

This appendix ensures IOCX can:

- extract valid URLs, domains, and IPs
- ignore malformed, reversed, split, or obfuscated fragments
- handle punycode, IPv6, and mixed‑script domains
- operate correctly inside a PE file’s `.obfs` section
- maintain strict correctness under adversarial conditions

The `franken_url_domain_ip.full.exe` fixture is the canonical test for validating the robustness of IOCX’s URL, domain, and IP extractors under extreme noise and obfuscation.
