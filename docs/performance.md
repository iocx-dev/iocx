# **IOCX Performance Guarantees**

IOCX is engineered for **predictable, low‑latency static analysis** across text, buffers, and Windows PE files.
This document defines the **performance guarantees** that every release must uphold.
All guarantees are enforced through automated CI performance tests.

> **IOCX must remain fast, stable, and deterministic — even under adversarial or malformed inputs.**

---

# **1. Throughput Summary (v0.7.1 Benchmarks)**

The table below reflects measured performance on reference hardware under CI‑controlled conditions.

| Subsystem                          | Input Type        | Size   | Time         | Throughput     |
|------------------------------------|-------------------|--------|--------------|----------------|
| **Raw IOC extraction (domains)**   | Text              | 1 MB   | **0.0033 s** | **~300 MB/s**  |
| **Raw IOC extraction (crypto)**    | Text              | 1 MB   | **0.0037 s** | **~270 MB/s**  |
| **Raw IOC extraction (filepaths)** | Text              | 1 MB   | **0.0040 s** | **~250 MB/s**  |
| **Raw IOC extraction (IP)**        | Text              | 1 MB   | **0.0064 s** | **~156 MB/s**  |
| **Pathological IPv6 blob**         | IPv6‑dense text   | 1 MB   | **0.0004 s** | **~2500 MB/s** |
| **Pathological ETH‑like blob**     | Crypto‑dense text | 1 MB   | **0.0012 s** | **~830 MB/s**  |
| **Typical PE**                     | 39 KB PE          | 39 KB  | **0.0132 s** | ~6–15 MB/s     |
| **Typical PE (with heuristics)**   | 39 KB PE          | 39 KB  | **0.0153 s** | ~6–15 MB/s     |
| **Adversarial dense PE**           | 1.5 MB PE         | 1.5 MB | **0.1977 s** | **~7.6 MB/s**  |
| **Malformed PE (“Franken”)**       | 64 KB PE          | 64 KB  | **0.0017 s** | N/A            |
| **Full engine (non‑PE)**           | 1 MB text         | 1 MB   | **0.0411 s** | —              |

**Key takeaways:**

- **Raw IOC extraction:** 150–300 MB/s
- **Typical PE:** ~13–15 ms
- **Adversarial PE:** ~0.197 s
- **Worst‑case text blobs:** sub‑millisecond to low‑millisecond

---

# **2. Raw IOC Extraction Guarantees**

Raw IOC extraction is the **fast path** (no PE parsing, no heuristics).

### **Guaranteed Baseline**
- **≤ 10 ms** for 1 MB mixed IOC‑rich text
- **≤ 5 ms** for crypto‑dense or IPv6‑dense blobs

### **Measured Performance**
```
domains !MB: 0.0033s
crypto 1MB: 0.0037s
filepaths 1MB: 0.0040s
IP 1MB: 0.0064s
IPv6 blob: 0.0004s
ETH blob: 0.0012s
Punycode blob: 0.0125s
```

### **Guarantee**
- Strict **O(n)** linear scanning
- No regex backtracking
- No pathological slow paths

---

# **3. Filepath Extraction Guarantees**

### **Guaranteed Baseline**
- **≤ 15 ms** for 1 MB mixed content
- **≤ 50 ms** for deeply nested or adversarial paths

### **Measured Performance**
```
filepaths 1MB mixed-content: 0.0040s
pathological deep UNIX path: 0.0248s
```

### **Guarantee**
- No recursion
- No exponential behaviour

---

# **4. IP Extraction Guarantees**

### **Guaranteed Baseline**
- **≤ 15 ms** for 1 MB mixed content
- **≤ 5 ms** for IPv6‑dense blobs

### **Measured Performance**
```
IP 1MB mixed-content: 0.0064s
pathological IPv6 blob: 0.0004s
```

### **Guarantee**
- IPv6 detector remains sub‑millisecond
- No catastrophic parsing behaviour

---

# **5. Crypto Extraction Guarantees**

### **Guaranteed Baseline**
- **≤ 10 ms** for 1 MB mixed crypto text
- **≤ 5 ms** for pathological ETH/BTC‑like blobs

### **Measured Performance**
```
crypto 1MB mixed-content: 0.0037s
pathological ETH-like blob: 0.0012s
```

### **Guarantee**
- Full Base58Check validation remains linear
- No backtracking or exponential behaviour

---

# **6. Domain Extraction Guarantees**

### **Guaranteed Baseline**
- **≤ 5 ms** for 1 MB mixed domain text
- **≤ 15 ms** for pathological punycode-like blobs

### **Measured Performance**
```
domains 1MB mixed-content: 0.0033s
pathological punycode-like blob: 0.0125s
```

### **Guarantee**
- domains detector remains sub‑millisecond
- No catastrophic parsing behaviour

---

# **7. Typical PE Analysis Guarantees**

### **Guaranteed Baseline**
- **≤ 20 ms** for a typical 30–60 KB PE
- Heuristics must not materially degrade performance

### **Measured Performance**
```
typical PE: 0.0132s
typical PE (heuristics): 0.0153s
```

### **Guarantee**
- Deterministic PE parsing
- Minimal overhead from heuristics

---

# **8. Malformed PE (“Franken”) Guarantees**

Malformed or adversarial PEs must not degrade performance.

### **Guaranteed Baseline**
- **≤ 20 ms** for malformed PEs
- No hangs, crashes, or exponential fallback behaviour

### **Measured Performance**
```
engine franken PE: 0.0017s
```

### **Guarantee**
- Deterministic structural heuristics
- No repeated scanning
- No speculative parsing loops

---

# **9. Adversarial Dense PE Guarantees**

### **Guaranteed Baseline**
- **≤ 250 ms** for 1.5 MB adversarial PEs

### **Measured Performance**
```
dense PE (1.5MB): 0.1977s
```

### **Guarantee**
- Stable under high‑entropy sections
- Stable under corrupted RVA/section tables
- Stable under adversarial import/TLS structures

---

# **10. Scaling Guarantees**

IOCX must maintain **strictly linear scaling** with respect to input size.

### **Measured Scaling**
```
300KB → ~0.001s
600KB → ~0.002s
1000KB → ~0.0029–0.0069s
1500KB → ~0.0044–0.0080s
```

### **Guarantee**
- No superlinear behaviour
- No quadratic or exponential paths

---

# **11. CI Enforcement**

Performance tests enforce:

- Upper‑bound thresholds for each subsystem
- Linear scaling checks
- No regression tolerance beyond jitter
- Hard failure if any guarantee is violated

---

# **12. Philosophy**

IOCX is designed to be:

- **Fast on normal inputs**
- **Fast on adversarial inputs**
- **Fast on malformed inputs**

Performance is a **core contract**, not an optimisation.
