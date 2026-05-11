# **IOCX Structural Validation & Deterministic Heuristics**
### *The Definitive Architecture of a Deterministic Static Analysis Engine*

Modern malware analysis tools often rely on heuristics that are opaque, unstable, or dependent on runtime behaviour. IOCX takes a different approach.
It begins with a foundation of **deterministic structural validators** — pure, static, reproducible checks that establish the *truth* of a binary’s layout.
Only after structural truth is established do heuristics interpret that truth.

This document explains the validator suite, the deterministic principles behind it, and how IOCX builds heuristics on top of a stable structural core.

---

# **1. Philosophy: Deterministic Structural Truth**

IOCX is built on a simple idea:

> **If you cannot trust the structure of a binary, you cannot trust anything derived from it.**

Every validator in IOCX is:

- **Deterministic** — no randomness, no environment dependence, no external data.
- **Snapshot‑stable** — identical input → identical output, across machines and versions.
- **Adversarial‑robust** — safe under malformed, truncated, or intentionally corrupted binaries.
- **Side‑effect‑free** — pure functions, no mutation, no execution, no network.
- **Composable** — each validator produces structural truth; heuristics interpret it.

This is the opposite of “guessing.”
This is **structural verification**.

---

# **2. The Validator Suite**
Each validator inspects a different subsystem of the PE format.
Together, they form a complete structural model of the binary.

Below is the definitive description of each validator and the structural invariants it enforces.

---

# **2.1 Entropy Validator**
### *Detects anomalous entropy patterns across sections, overlays, and regions.*

The entropy validator establishes:

- High‑entropy sections (possible packing or encryption).
- Very low entropy in large sections (possible padding or corruption).
- High‑entropy overlays (packed payloads appended to the file).
- High entropy in specific regions (resources, relocations, imports, TLS, certificates).
- Uniform entropy across sections (indicative of packers that homogenise data).

All thresholds are fixed constants.
All decisions are deterministic.
No entropy‑based heuristic is emitted here — only structural facts.

---

# **2.2 Entrypoint Validator**
### *Verifies that the binary’s execution entrypoint is structurally valid.*

This validator ensures:

- EntryPoint is positive and non‑zero.
- EntryPoint is not inside headers.
- EntryPoint maps to a real section.
- EntryPoint is inside an executable section.
- EntryPoint is not inside `.rsrc`, `.reloc`, or other non‑code regions.
- EntryPoint is not inside discardable or zero‑length sections.
- EntryPoint does not map into overlay data.

This validator is one of the strongest structural correctness checks in IOCX.
It prevents false heuristics by ensuring the EP is meaningful before interpretation.

---

# **2.3 Optional Header Validator**
### *Validates the core invariants of the PE Optional Header.*

This validator enforces:

- `SizeOfImage` ≥ max section end.
- `SizeOfHeaders` aligned to `FileAlignment` and ≥ actual header size.
- `SectionAlignment` ≥ `FileAlignment` and power‑of‑two.
- `FileAlignment` power‑of‑two and within 512–64K.
- `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData` ≥ section totals.
- `ImageBase` 64K‑aligned.
- `NumberOfRvaAndSizes` within valid range and ≥ actual directories.
- `SizeOfImage` aligned to `SectionAlignment`.

These checks ensure the binary’s declared layout matches its actual layout.

---

# **2.4 Resources Validator**
### *Validates the entire resource tree: directories, entries, and data blobs.*

This validator performs:

- Recursive directory validation with loop detection.
- Bounds checking for every directory and data entry.
- Raw and virtual overlap detection with other sections.
- Overlay overlap detection.
- Zero‑length directory and zero‑length data detection.
- String table bounds validation.

Resource trees are a common place for corruption and obfuscation.
This validator ensures the `.rsrc` section is structurally sane before heuristics interpret it.

---

# **2.5 RVA Graph Validator**
### *Validates all PE data directories and their mapping to sections.*

This validator enforces:

- No negative RVAs or sizes.
- Zero‑RVA directories with non‑zero size are flagged.
- Directories must not lie inside headers.
- Directories must not exceed `SizeOfImage`.
- Directories must map to exactly one section.
- Directories must not span multiple sections.
- Directories must not overlap each other.
- Directories must not map into overlay data.
- Zero‑length sections are treated as invalid mapping targets.

This validator is the backbone of structural correctness for imports, exports, resources, relocations, TLS, and security directories.

---

# **2.6 Sections Validator**
### *Validates section flags, alignment, ordering, and overlap.*

This validator enforces:

- RWX sections (executable + writable).
- Code flag without executable flag.
- Code‑like names without executable flag.
- Non‑ASCII or padding section names.
- Impossible flag combinations (discardable + executable + writable).
- Raw alignment to `FileAlignment`.
- Sections overlapping headers.
- Zero‑length sections.
- Discardable executable sections.
- Contradictory flags (exec/write/code without read).
- Raw overlap between sections.
- Virtual overlap between sections.
- Raw and virtual ordering must be ascending.

This validator is the structural heart of IOCX.
It ensures the section table is coherent, non‑overlapping, and meaningful.

---

# **2.7 Signature Validator**
### *Validates WIN_CERTIFICATE structures.*

This validator enforces:

- Flag/metadata symmetry.
- Single certificate (multiple certificates flagged).
- Certificate length ≥ 8.
- Valid revision (0x0100 or 0x0200).
- Valid certificate type (0x0001 or 0x0002).
- Certificate within file bounds.
- Certificate not overlapping overlay.
- Certificate not overlapping any section.

This ensures the Authenticode block is structurally valid before any trust decisions are made.

---

# **2.8 TLS Validator**
### *Validates TLS directory and callback structure.*

This validator enforces:

- At most one TLS directory.
- TLS directory has valid start/end range.
- TLS callbacks pointer is non‑zero.
- TLS callbacks lie inside TLS range.
- TLS callbacks map to a real section.
- TLS callbacks lie in an executable section.
- TLS callbacks not inside headers.
- TLS callbacks not inside overlay.

TLS callbacks are a common malware trick; this validator ensures the structure is sound before heuristics interpret it.

---

# **3. Deterministic Heuristics Layer**
### *Heuristics interpret structural truth — they never override it.*

Once validators establish structural truth, heuristics interpret that truth to produce higher‑level signals.

Heuristics include:

## **3.1 Packer Heuristics**
- UPX‑like section names.
- High‑entropy sections ≥ 7.5 with raw size ≥ 1 KB.

## **3.2 Anti‑Debug Heuristics**
- Imports of anti‑debug APIs.
- Imports of timing APIs.
- RWX sections (structurally validated first).

## **3.3 Import Anomaly Heuristics**
- Large import tables.
- High ratio of ordinal‑only imports.
- GUI subsystem importing kernel‑mode DLLs.

## **3.4 Structural Anomaly Heuristics**
Every structural issue becomes a heuristic signal:

```
pe_structure_anomaly / <reason_code>
```

Except entropy‑specific issues, which are handled by packer heuristics.

This ensures:

- No duplication.
- No double‑counting.
- No contradictory signals.
- A clean separation between *facts* and *interpretation*.

---

# **4. Why Determinism Matters**

Most IOC extractors and static analysis tools suffer from:

- nondeterministic regex engines
- inconsistent PE parsing
- version‑to‑version instability
- environment‑dependent behaviour
- heuristic drift
- false positives under adversarial input

IOCX avoids all of this by design.

### **Determinism gives you:**

- **Snapshot‑stable output** — identical input → identical output.
- **Reproducibility** — critical for DFIR, SOC automation, and CI/CD.
- **Adversarial robustness** — malformed binaries cannot destabilise the engine.
- **Predictable heuristics** — heuristics interpret structural truth, not guesses.
- **Trustworthiness** — every detection is explainable and traceable.

This is why IOCX is not “just another IOC extractor.”
It is a **structural correctness engine**.

---

# **5. The IOCX Model: Structural Truth → Deterministic Heuristics → Reliable IOCs**

The pipeline is:

1. **Parse** the binary into a stable internal representation.
2. **Validate** every subsystem with deterministic structural validators.
3. **Record** structural issues in `analysis["structural"]`.
4. **Interpret** structural truth with deterministic heuristics.
5. **Extract** IOCs from a stable, verified structural model.

This ensures IOC extraction is:

- safe
- predictable
- automatable
- reproducible
- adversarial‑robust

Exactly what DFIR teams, SOC pipelines, and CI/CD systems require.

---

# **6. The IOCX Guarantee**

IOCX guarantees:

> **No nondeterminism. No hidden heuristics. No unstable behaviour.
> Just structural truth, interpreted deterministically.**

This is the foundation of the entire engine.
This is why IOCX is trusted.
This is why its output is stable.
This is why it scales to automation.
