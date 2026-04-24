# IOCX Performance Guarantee

IOCX is engineered to deliver **predictable, low‑latency extraction and analysis** across a wide range of binary formats and content types. This document defines the performance guarantees that the engine must uphold across releases. These guarantees are enforced through automated performance tests that run in CI.

The goal is simple:
> **IOCX must remain fast, stable, and scalable — even under adversarial or malformed inputs.**

## Throughput Summary

The following table compares IOCX’s measured throughput across different subsystems and workloads. All tests are run on reference hardware under CI‑controlled conditions.

| **Subsystem**                    | **Input Type**             | **Size** | **Measured Time** | **Throughput**   |
|----------------------------------|----------------------------|----------|-------------------|------------------|
| IOC extraction (mixed content)   | Flat text (URLs, IPs, BTC) | 1 MB     | **0.0360 s**      | **≈ 28 MB/s**    |
| IOC extraction (pathological)    | Deep UNIX path             | 1 MB     | **0.0247 s**      | **≈ 40 MB/s**    |
| IOC extraction (IPv6 blob)       | Pathological IPv6 patterns | 1 MB     | **0.0004 s**      | **≈ 2500 MB/s**  |
| Crypto extraction                | Mixed crypto text          | 1 MB     | **0.0022 s**      | **≈ 450 MB/s**   |
| Crypto extraction (pathological) | ETH‑like blob              | 1 MB     | **0.0012 s**      | **≈ 830 MB/s**   |
| PE structural analysis           | Malformed PE (“Franken”)   | 64 KB    | **0.0028 s**      | N/A (non‑linear) |
| Full engine (PE + IOC)           | 1 MB PE                    | 1 MB     | **0.0360 s**      | **≈ 28 MB/s**    |

*Notes*

- Throughput for PE parsing is not expressed in MB/s because PE analysis includes structural heuristics, RVA validation, and metadata extraction rather than pure linear scanning.
- Pathological cases are intentionally adversarial inputs designed to stress specific detectors.
- All results demonstrate strictly linear scaling with respect to input size

## 1. IOC Extraction Throughput (1MB Mixed‑Content Text)

This benchmark measures the performance of the IOC extraction pipeline only. It does not involve PE parsing, binary metadata extraction, or structural heuristics.

The test feeds IOCX a 1MB flat text blob composed of:

- repeated URLs
- Windows registry paths
- Bitcoin‑like crypto strings
- IPv4 addresses
- general ASCII noise

This represents a realistic high‑entropy, mixed‑IOC workload similar to what appears in logs, telemetry, and decoded buffers.

### Guaranteed Baseline

IOCX must process **1MB of mixed IOC-like text in under 50ms** on reference hardware.

### Current Performance

```
engine end-to-end 1MB: 0.0360s
```

- This benchmark reflects pure IOC scanning throughput, demonstrating:
   - **linear O(n)** behaviour
   - no regex backtracking
   - no pathological slow paths
   - cache‑friendly tokenisation
   - stable performance across mixed content
- This test isolates the text‑scanning subsystem and confirms that IOCX can process large volumes of unstructured IOC‑rich text efficiently.

## 2. Crypto Extraction Performance

### Guaranteed Baseline

- IOCX must extract crypto‑related IOCs from **1MB of mixed content in under 10ms**.
- Pathological ETH/BTC‑like blobs must complete in **under 5ms**.

### Current Performance

```
crypto 1MB mixed-content: 0.0022s
pathological ETH-like blob: 0.0012s
```

These results confirm:

- no catastrophic regex behaviour
- no backtracking
- linear scanning performance

## 3. Filepath Extraction Performance

### Guaranteed Baseline

- IOCX must extract filepaths from **1MB of mixed content in under 15ms**.
- Deeply nested or pathological paths must complete in **under 50ms**.

### Current Performance

```
filepaths 1MB mixed-content: 0.0040s
pathological deep UNIX path: 0.0247s
```

This demonstrates:

- predictable behaviour under worst‑case nesting
- no recursion or exponential slowdowns

## 4. IP Extraction Performance

### Guaranteed Baseline

- IOCX must extract IPv4/IPv6 IOCs from **1MB of mixed content in under 15ms**.
- Pathological IPv6 blobs must complete in **under 5ms**.

### Current Performance

```
IP 1MB mixed-content: 0.0067s
pathological IPv6 blob: 0.0004s
```

The IPv6 detector remains extremely fast even under adversarial patterns.

## 5. Malformed PE Handling (Franken Guarantee)

Malformed or adversarial PE files must not degrade performance.

### Guaranteed Baseline

- IOCX must fully analyse malformed PEs in **under 20ms**.
- No crashes, hangs, or exponential fallback behaviour.

### Current Performance

```
engine franken PE: 0.0028s
```

This confirms:

- deterministic structural heuristics
- no repeated scanning
- no speculative parsing loops
- no performance cliffs under malformed conditions

## 6. Scaling Behaviour

IOCX must maintain **strictly linear** scaling with respect to input size.

### Current Scaling Profile

```
300KB → ~0.001s
600KB → ~0.002s
1000KB → ~0.004–0.006s
1500KB → ~0.005–0.008s
```

This behaviour is monitored in CI to detect regressions.

## 7. CI Enforcement

Performance tests run automatically and enforce:

- **Upper‑bound thresholds** for each category
- **Linear scaling checks**
- **No regression tolerance** beyond a small jitter margin
- **Hard failure** if any test exceeds its guarantee

This ensures IOCX remains fast across all future releases.

## 8. Philosophy

IOCX is designed to be:

- **Fast on normal inputs**
- **Fast on adversarial inputs**
- **Fast on malformed inputs**

Performance is not an afterthought — it is a core contract of the engine.
