# **IOCX Structural Validation & Deterministic Heuristics**
### *The Architecture of a Fully Deterministic Static Analysis Engine*

Modern malware analysis tools rely heavily on opaque heuristics, inconsistent parsing, and environment‑dependent behaviour. IOCX takes a fundamentally different approach.

It begins with **deterministic structural validators** — pure, reproducible checks that establish the *truth* of a binary’s layout.
Only after structural truth is established do heuristics interpret that truth.

This document defines the validator suite, the deterministic principles behind it, and how IOCX builds reliable heuristics on top of a stable structural core.

---

# **1. Philosophy: Structural Truth Above All**

IOCX is built on a single principle:

> **If you cannot trust the structure of a binary, you cannot trust anything derived from it.**

Every validator in IOCX is:

- **Deterministic** — no randomness, no environment dependence, no external data.
- **Snapshot‑stable** — identical input → identical output, across machines and versions.
- **Adversarial‑robust** — safe under malformed, truncated, or intentionally corrupted binaries.
- **Side‑effect‑free** — pure functions; no execution, no mutation, no network.
- **Composable** — each validator produces structural truth; heuristics interpret it.

This is not guesswork.
This is **structural verification**.

---

# **2. The Validator Suite**
Each validator inspects a distinct subsystem of the PE format.
Together, they form a complete, deterministic structural model of the binary.

Some structural metadata extracted by parsers is **producer-facing**: it exists to enable validators and heuristics, not to be exposed via the public IOC schema. Examples include the export and delay-load structural details. Other structural metadata is **consumer-facing** and intended for public exposure: version-info string fields are an example of this, planned for promotion in a future release.

---

# **2.1 Entropy Validator**
### *Detects anomalous entropy patterns across sections, overlays, and regions.*

The entropy validator establishes:

- High‑entropy sections (possible packing or encryption).
- Very low entropy in large sections (padding or corruption).
- High‑entropy overlays (packed payloads appended to the file).
- High entropy in specific regions (resources, relocations, imports, TLS, certificates).
- Uniform entropy across sections (homogenised packer output).

All thresholds are fixed constants.
All decisions are deterministic.
No entropy‑based heuristic is emitted here — only structural facts.

---

# **2.2 Entrypoint Validator**
### *Ensures the declared execution entrypoint is structurally valid.*

This validator ensures:

- EntryPoint is non‑zero and positive.
- EntryPoint is not inside headers.
- EntryPoint maps to a real section.
- EntryPoint lies in an executable section.
- EntryPoint is not inside `.rsrc`, `.reloc`, or other non‑code regions.
- EntryPoint is not inside discardable or zero‑length sections.
- EntryPoint does not map into overlay data.

This prevents false heuristics by ensuring the EP is meaningful before interpretation.

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
- `NumberOfRvaAndSizes` valid and ≥ actual directories.
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

Resource trees are a common site of corruption and obfuscation.
This validator ensures `.rsrc` is structurally sane before heuristics interpret it.

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
- Zero‑length sections are invalid mapping targets.

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

This validator ensures the section table is coherent, non‑overlapping, and meaningful.

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

# **2.9 Load Config Directory Validator**
### *Validates the integrity and internal consistency of the Load Configuration Directory.*

The Load Config Directory contains metadata used by CFG, SEH, security cookies, and compiler‑generated hardening features.
IOCX validates it with the same deterministic rigor as other critical subsystems.

This validator enforces:

- Minimum size requirements (PE32 vs PE32+).
- Truncation detection using actual file length.
- Guard CF metadata consistency.
- Security cookie placement and permissions.
- SEH table integrity.
- Directory/header consistency.

This closes one of the most subtle structural attack surfaces in the PE format.

---

# 2.10 Version‑Info Validator
## Validates the structural integrity of the VS_VERSIONINFO blob extracted from the RT_VERSION resource.

This validator performs:

- Top‑level envelope validation: placement within .rsrc, szKey conformance to "VS_VERSION_INFO", and wLength consistency with the buffer.
- VS_FIXEDFILEINFO signature and struct‑version validation.
- StringFileInfo / StringTable / String hierarchy traversal, with per‑substructure length and key‑format checks.
- VarFileInfo / Var validation, including DWORD‑alignment of the Translation array.
- Deterministic leaf selection: when multiple RT_VERSION leaves exist, the parser sorts by (name_id, language_id) so the chosen blob is stable across runs.

VS_VERSIONINFO is a recursive, length‑prefixed nested‑structure format with multiple optional children, variable‑length UTF‑16 keys, and DWORD‑alignment rules between every field. It is one of the most failure‑prone surfaces in the PE format for general‑purpose parsers — small differences in how a parser handles truncated wLength fields, malformed szKey strings, or misaligned Translation arrays produce divergent output across tools and across versions of the same tool.

The version‑info parser is implemented as a pure struct‑level decoder with no reliance on external library interpretation:

- Length and alignment arithmetic is performed against the raw buffer using fixed PE‑spec formulas.
- All loops are bounded by wLength, child_end, and body_end so no walk can exceed the input.
- Sub‑structure failures emit deterministic tombstone tags in an errors list rather than raising exceptions or being silently swallowed.
- Leaf selection across multiple RT_VERSION entries uses a stable sort key, not parser iteration order.

This ensures that for any given input blob, the parser produces the same decoded dict on every run, on every platform, regardless of library version. Malformed inputs produce predictable structural errors rather than partial parses or library‑specific exceptions.

The validator then maps these structural states to a small, well‑defined set of reason codes (`RESOURCE_VERSIONINFO_INVALID_HEADER`, `_INVALID_FIXEDINFO`, `_INVALID_STRINGFILEINFO`, `_INVALID_VARFILEINFO`), which downstream heuristics and IOC consumers can rely on as a stable contract.

Version‑info is a high‑signal forensic surface: CompanyName, OriginalFilename, and ProductVersion are routinely impersonated in adversarial samples. Deterministic extraction is a prerequisite for treating these fields as reliable triage signals.

---

# 2.11 Exports Validator
## Validates the structural integrity of the PE export table extracted by parser_exports.

This validator performs:

- Top‑level decode failure detection and short‑circuit
- Export directory placement within SizeOfImage
- Truncation reporting across EAT, ENPT, and EOT sub‑tables
- Header consistency checks (declared counts vs declared RVAs, name count vs function count)
- Per‑entry name pointer validation: RVA, encoding, ordinal index bounds
- Export Name Pointer Table sort order (PE spec requires lexicographic ordering for binary search)
- Per‑entry function validation: ordinal range, address RVA bounds, forwarder string format

Absence of an export directory is not treated as a structural defect — most EXE files legitimately have no exports.

The export table is the second‑most parser‑sensitive surface in the PE format after VS_VERSIONINFO. Three properties make general‑purpose export parsers prone to divergent output: the EAT can contain a mix of function RVAs and forwarder string pointers distinguished only by whether the RVA falls inside the export directory; the ENPT is required to be sorted but malformed binaries routinely violate this; and the EOT cross‑references the EAT by index, creating a join that breaks silently if either side is truncated.

The exports parser reads all four critical tables (header, EAT, ENPT, EOT) directly from raw bytes via struct.unpack_from, with bounded array reads and per‑position fallback to None when bytes are missing. The validator's per‑entry checks treat the parser's tombstone tags as a stable contract — each tag maps to a deterministic reason code and sub‑reason. Priority lists govern which sub‑reason wins when an entry carries multiple malformations.

This ensures that for any given malformed export table, the validator produces the same set of reason codes on every run, regardless of platform or pefile version. Forwarder strings are validated against the PE spec's DllName.SymbolName and DllName.#Ordinal grammar via a single conservative regex, not by attempting runtime resolution.

---

## 2.12 Delay-Load Imports Validator

### Validates the structural integrity of the PE delay-load import directory and its descriptor array.

This validator performs:

- Top-level decode failure detection and short-circuit for unrecoverable directory placement.
- Delay-load directory placement within `SizeOfImage`.
- Truncation reporting across the descriptor array and per-descriptor INT and IAT sub-tables.
- Per-descriptor structural validation: zero-RVA sub-tables, sub-table read failures, length-budget exhaustion.
- DLL name string validation: RVA presence, readability, NUL termination, printable ASCII compliance.
- INT/IAT parallel-array length consistency check (the strongest single signal of malformation).
- v0 (legacy VA-mode) attribute detection for pre-Windows 2000 binaries.
- Per-entry validation of INT thunks and IMAGE_IMPORT_BY_NAME structures, including ordinal validity, hint readability, and name structural correctness.

Absence of a delay-load directory is not treated as a structural defect — most binaries do not use delay-loading. Bound state (`bound_iat_rva != 0`) is captured by the parser but not flagged as anomalous; bound delay-load is the normal pattern for Microsoft-shipped binaries.

The delay-load directory is one of the most divergence-prone surfaces in the PE format. Three properties make general-purpose delay-load parsers prone to inconsistent output:

The directory is a chain of variable-content structures whose interpretation depends on a single bit in the Attributes field — v0 binaries (Attributes bit 0 clear) use raw virtual addresses requiring ImageBase subtraction, while v1 binaries use RVAs directly. Many parsers do not implement v0 support and silently coerce the values, producing output that differs across tool versions and across binaries depending on which mode is detected.

The INT and IAT are parallel arrays whose elements must agree on length, but whose interpretations diverge: an INT entry is a thunk describing an import (ordinal or hint+name pointer); an IAT entry is initially a mirror of the INT thunk and later becomes a runtime-resolved address. Bound binaries have the IAT pre-populated with bound addresses, breaking the mirror property. Parsers that assume the mirror property unconditionally produce wrong results on bound binaries; parsers that assume the bound property unconditionally produce wrong results on unbound binaries.

The descriptor array is terminated by a zero-filled IMAGE_DELAY_IMPORT_DESCRIPTOR rather than by a count field. Parsers that trust the directory's declared size and parsers that walk until terminator both work on well-formed binaries but disagree on truncated ones — the former stops at declared end and reports a clean truncation; the latter reads past declared end if a terminator is absent, producing data that the former considers out-of-bounds.

The delay-load parser is implemented as a pure `struct`-level decoder over `pe.get_data`-acquired byte buffers:

- The 32-byte IMAGE_DELAY_IMPORT_DESCRIPTOR structure is unpacked via a single `struct.unpack_from` call. No reliance on pefile's `DIRECTORY_ENTRY_DELAY_IMPORT` interpretation.
- The Attributes v1 flag is captured from the raw value; v0 binaries are reported via a dedicated reason code rather than silently coerced. The PE32+ vs PE32 distinction is captured from `OPTIONAL_HEADER.Magic` once at parse-start and used for the entire walk to determine thunk size (DWORD vs QWORD).
- The descriptor array walk has both an explicit zero-descriptor terminator check and a hard count limit (4096), with distinct truncation tags for each termination cause.
- INT and IAT thunk arrays are walked with the same dual-bounded strategy: zero terminator detection plus hard limit (16384 per descriptor). Each thunk's struct.unpack failure is reported deterministically.
- Bound state is detected by `bound_iat_rva != 0` (a single byte-level field comparison), not by inference from IAT value patterns. The detection is bit-exact across runs.
- INT/IAT length mismatch is detected by a single integer comparison after both arrays are walked. The validator emits a dedicated reason code rather than letting the inconsistency propagate as per-entry errors.
- The IMAGE_IMPORT_BY_NAME structure is read with a bounded scan (1024 bytes) and validated against printable ASCII rules. Substructure failures emit deterministic tombstone tags in per-entry `errors` lists.

---

# **3. Deterministic Heuristics Layer**
### *Heuristics interpret structural truth — they never override it.*

Once validators establish structural truth, heuristics interpret that truth to produce higher‑level signals.

Heuristics include:

- **Packer indicators** (UPX‑like names, high entropy).
- **Anti‑debug imports**.
- **Timing APIs**.
- **RWX sections** (validated structurally first).
- **Import anomalies** (ordinal‑only imports, large tables).
- **Structural anomaly heuristics** — every structural issue becomes a deterministic signal.

Heuristics never contradict validators.
They only interpret validated truth.

---

# **4. Why Determinism Matters**

Most static analysis tools suffer from:

- nondeterministic regex engines
- inconsistent PE parsing
- version‑to‑version drift
- environment‑dependent behaviour
- heuristic instability
- false positives under malformed input

IOCX avoids all of this by design.

Determinism gives:

- **Snapshot‑stable output** — identical input → identical output.
- **Reproducibility** — essential for DFIR, SOC automation, CI/CD.
- **Adversarial robustness** — malformed binaries cannot destabilise analysis.
- **Predictable heuristics** — interpretation of truth, not guesses.
- **Trustworthiness** — every detection is explainable and traceable.

---

# **5. The IOCX Model: Structural Truth → Deterministic Heuristics → Reliable IOCs**

The pipeline:

1. **Parse** the binary into a stable internal representation.
2. **Validate** every subsystem with deterministic validators.
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

> **No nondeterminism. No hidden heuristics. No unstable behaviour.
> Just structural truth, interpreted deterministically.**

This is the foundation of the engine.
This is why IOCX is trusted.
This is why its output is stable.
This is why it scales to automation.
