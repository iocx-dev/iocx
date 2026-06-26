# **v0.7.5 — Unreleased**

## Added

- **Resource directory hierarchy enforcement.** The resource validator now
  tracks tree depth and enforces the PE specification's Type → Name → Language
  layering. Two new reason codes are emitted:
  - `RESOURCE_DIRECTORY_LANGUAGE_NOT_ID` — a depth-2 (Language layer) entry
    uses a name instead of an integer LCID.
  - `RESOURCE_DATA_AT_INVALID_DEPTH` — a data leaf appears outside the
    Language layer.
- **Deterministic VS_VERSIONINFO extraction.** New `pe_version_info` parser
  module decodes the version-info envelope, VS_FIXEDFILEINFO, StringFileInfo
  and VarFileInfo structures purely from bytes using `struct.unpack_from`.
  Leaf selection across multiple RT_VERSION entries is deterministic, sorted
  by `(name_id, language_id)`. The decoder never raises; sub-structure
  failures emit tombstone tags in an `errors[]` list.
- **Version-info structural validator.** New `validator_version_info` module
  maps parser output to four new reason codes:
  - `RESOURCE_VERSIONINFO_INVALID_HEADER` — placement, `szKey`, or `wLength`
    malformed.
  - `RESOURCE_VERSIONINFO_INVALID_FIXEDINFO` — VS_FIXEDFILEINFO signature or
    struct version wrong, or parse failed.
  - `RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO` — StringFileInfo,
    StringTable, or String malformed.
  - `RESOURCE_VERSIONINFO_INVALID_VARFILEINFO` — VarFileInfo or Var malformed,
    or Translation array not DWORD-aligned.

  Absence of RT_VERSION is not treated as a structural defect.
- **Precise internal metadata typing.** `InternalMetadata.resources_struct` is
  now `Optional[ResourcesStruct]` with a fully-typed `ResourceEntry` shape
  replacing `List[Any]`. New `VersionInfoStruct` and its sub-types
  (`FixedFileInfo`, `StringFileInfo`, `StringTable`, `VarFileInfo`,
  `VarEntry`, `Translation`) are declared in the schema.
- **Deterministic export table extraction.** New `pe_exports` module
  decodes the 40-byte `IMAGE_EXPORT_DIRECTORY` header, the Export Address
  Table, Export Name Pointer Table, and Export Ordinal Table purely from
  bytes using `struct.unpack_from`. Forwarder detection follows the PE
  spec rule (address RVA falls within the export directory range).
  Name and forwarder string reads are bounded; the decoder never raises;
  sub-structure failures emit tombstone tags in `truncations[]` and
  per-entry `errors[]`.
- **Export table structural validator.** New `exports` module
  maps parser output to ten new reason codes:
  - `EXPORT_DIRECTORY_INVALID_HEADER` — header malformed or declared
    counts inconsistent with declared array RVAs.
  - `EXPORT_DIRECTORY_OUT_OF_BOUNDS` — directory extends past
    `SizeOfImage`.
  - `EXPORT_TABLE_TRUNCATED` — declared sub-table size exceeds available
    bytes (per-table emission via `details["table"]`).
  - `EXPORT_NAME_RVA_INVALID` — name pointer RVA unusable
    (priority-resolved sub-reasons: `name_rva_missing`, `name_rva_zero`,
    `read_failed`, `unterminated`).
  - `EXPORT_NAME_NOT_ASCII` — name decoded but contains non-printable
    bytes (priority-resolved sub-reasons: `non_ascii`,
    `name_not_printable_ascii`).
  - `EXPORT_NAME_POINTER_TABLE_UNSORTED` — ENPT violates the PE-spec
    requirement that names be sorted lexicographically for binary search.
  - `EXPORT_NAME_ORDINAL_INDEX_INVALID` — EOT entry missing or points
    outside the EAT.
  - `EXPORT_ORDINAL_OUT_OF_RANGE` — `Base + NumberOfFunctions - 1`
    exceeds 16-bit range.
  - `EXPORT_FUNCTION_RVA_INVALID` — function address RVA exceeds
    `SizeOfImage`.
  - `EXPORT_FORWARDER_MALFORMED` — forwarder string unreadable or
    violates `DllName.SymbolName` / `DllName.#Ordinal` grammar.

  Absence of an export directory is not treated as a structural defect;
  most EXEs legitimately have no exports.
- **Precise export-table typing.** New TypedDicts for `ExportStruct`,
  `ExportDirectoryHeader`, `ExportFunctionEntry`, and
  `ExportNamePointerEntry`. `InternalMetadata.export_struct` is typed as
  `Optional[ExportStruct]`.
- **Enriched resource metadata in CLI output.** The `_parse_resources`
  function now exposes a structured `ResourceEntry` for every resource
  in the PE, covering all four fields called out in requirement 4
  (type, size, language and codepage, entropy) plus the schema-declared
  `name`, `rva`, and `raw_offset` fields. Output is deterministic and
  JSON-safe.
- **Per-entry structured error reporting.** Resources whose data bytes
  cannot be read are no longer silently dropped from the output. Instead,
  the entry is emitted with an `errors` list populated with tombstone
  tags describing the failure:
  - `size_invalid` — declared size is zero or negative.
  - `rva_invalid` — data RVA is negative.
  - `data_out_of_bounds` — RVA + size exceeds the memory-mapped image.
  - `raw_offset_invalid` — `get_offset_from_rva` failed to resolve the
    file offset.

  This makes the resource count visible to consumers even when individual
  entries cannot be fully decoded.
- **Codepage field on resource entries.** The `CodePage` field from the
  PE resource data structure is now captured as `codepage` in the
  output, typed as `Optional[int]` (null when zero or absent).
- **Deterministic resource ordering.** The output list is sorted by
  `(type, language, rva)` to ensure snapshot stability across runs.
- **Per-resource Shannon entropy.** Computed over the resource's data
  bytes, rounded to 4 decimal places for snapshot stability. Entries
  with unreadable data produce `entropy: null` and the corresponding
  error tombstone.

## Changed

- **Resource parser hardens against corrupt RVAs.** `pe.get_offset_from_rva`
  calls are now guarded against `pefile.PEFormatError` and `AttributeError`.
  A corrupt RVA produces a `-1` sentinel in `raw_offset` rather than
  propagating the exception. The validator's existing `data_raw < 0` arm
  maps this to the existing `RESOURCE_DATA_OUT_OF_BOUNDS` reason code; no new
  code introduced.
- **Validator dispatcher order.** `validate_version_info` is registered
  between `validate_resources` and `validate_entropy`, reflecting its
  position as a payload-specific validator nested under the resource tree.
- **Validator dispatcher order.** `validate_exports` is registered
  between `validate_version_info` and `validate_entropy`, completing the
  structural validator chain ahead of the entropy/derived layer.
- **`ResourceEntry` schema expanded.** Fields are now `total=False`
  Optional to accommodate per-entry computation failures. New fields:
  `codepage`, `errors`. Existing fields retain their meanings; `name`,
  `rva`, and `raw_offset` are now populated where they were previously
  declared but absent from output.
- **`_decode_langid` returns `None` for undecodable LANGIDs.**
  Previously returned the magic string `"unknown"`, which conflated
  several distinct states (not provided, structurally invalid, primary
  language unmapped). The new behaviour returns `None` from every
  "cannot decode" path, allowing consumers to distinguish cleanly.
  The early-return guard `if langid < 0x0400` was removed; it was
  rejecting valid neutral-sublang LANGIDs (e.g., LANGID `0x0001`
  decodes correctly as `"ar"` for Arabic).
- **Resource entropy now computed over the correct byte range.**
  Previously sliced `get_memory_mapped_image()` with the raw file
  offset; now correctly uses the RVA. This was a regression introduced
  during the requirement 4 work and caught before snapshot stamping —
  entropy values now match the previous release's behaviour for all
  existing fixtures.

## Marked as RESERVE but consider removing in the future

- Dead `size == 0` branch in `validate_directory` (unreachable: `size` is
  derived from `len(entries)` and always ≥ 16).
- Unused `rsrc_raw` and `rsrc_raw_size` locals in the resource validator.

## Fixed

- Resource validator no longer silently returns when a directory's own RVA
  falls outside `.rsrc`. Behaviour previously suppressed any reporting for
  malformed directory placement.

## Documentation

- Reason-codes reference extended with two new subsections:
  *Resource Hierarchy Anomalies* and *Resource Version-Info Anomalies*.
- New validator documentation section (2.10) for the version-info validator,
  including an explicit determinism rationale paragraph.
- Brief clarifying note added to the resources validator section explaining
  the layering between resource-tree validation and payload validators
  nested beneath it.
- Reason-codes reference extended with a new top-level *Export Anomalies*
  section in three subsections (Directory, Name Pointer, Function Entry)
  and a dedicated *Export Sub-Reasons* taxonomy section documenting the
  `details["reason"]` contract for each code that carries one.
- New validator documentation section 2.11 for the exports validator with
  explicit determinism rationale.
- Resource metadata documentation extended to describe the new
  `ResourceEntry` shape, the `errors` field semantics, and the
  `codepage` field's `null`-on-absent convention.
- The `_decode_langid` semantics are documented inline: primary
  language and sublang decomposition, fallback to default region,
  fallback to primary-language-only, fallback to `None`.

## Internal

- 100% line and branch coverage on `pe_version_info`,
  `validator_version_info`, and the resource validator additions.
- Defensive-path coverage for every `except` clause via monkeypatched
  `struct.error` injection.
- Narrow-except negative tests confirm the parser's exception handling does
  not silently swallow exceptions outside `(PEFormatError, AttributeError)`.
- 100% line and branch coverage on `pe_exports` and
  `exports` validator.
- Defensive-path coverage via monkeypatched `struct.error` injection
  and narrow-except negative tests.
- One `# pragma: no cover` applied to a defensive return in the
  validator's `_first_unsorted_index` helper, documented inline as
  unreachable from the validator's call site.
- Memory-mapped image slicing uses the RVA (not the raw file offset),
  which is the correct index into `get_memory_mapped_image()` output.
- Float precision pinned at 4 decimal places for entropy, matching the
  precision convention used in other entropy-bearing fields elsewhere
  in IOCX.

## Compatibility

- **No reason-code remapping.** Existing fixture expected outputs are
  unchanged for all binaries that don't exercise the new pathways.
- **No public IOC schema changes.** Version-info data is currently exposed
  only in internal metadata and CLI rendering; public IOC schema exposure
  is deferred to a later release with a deliberate fixture corpus refresh.
- Invalid optional header fixtures JSON contracts updated: addition of export anomalies to heuristic output.
- Resource fixture snapshots refreshed to reflect new field shape and `language_name` semantics.
- **Resource output shape is additive but reformatted.** Consumers
  reading the `resources` field will see new keys (`codepage`,
  `errors`, `name`, `rva`, `raw_offset`) and may see additional
  entries that previously didn't appear (those with errors). Existing
  per-entry field meanings are unchanged.
- **`language_name` no longer returns the string `"unknown"`.**
  Consumers checking `language_name == "unknown"` will need to update
  to `language_name is None`. This is a deliberate semantic correction
  rather than a passive breaking change — the previous value was a
  magic-string sentinel that conflated several states.
- **Snapshot refresh required for any fixture with resources.** The
  `language_name` return change and the new fields will produce diffs
  in expected outputs. Refresh is mechanical via the existing fixture
  regeneration tooling.

## Known scheduled work

- Six single-anomaly fixtures targeting the new resource directory reason codes (specs queued;
  construction to follow).
- `pefile_usage_policy.md` documenting the deterministic-subset usage pattern
  (to be drafted alongside the reproducibility appendix work).
- Public IOC schema field for `version_info` (planned for a future release
  with corpus refresh and schema-version bump).
- Single-anomaly fixtures targeting the new export reason codes (specs
  drafted; construction to follow). Includes one negative-control
  fixture (`exp_forwarder_to_ordinal_valid`) demonstrating that the
  validator correctly accepts the spec-valid `#Ordinal` forwarder
  syntax without false positive.
- Resource fixtures targeting the new `errors` field paths
  (`size_invalid`, `rva_invalid`, `data_out_of_bounds`,
  `raw_offset_invalid`). Currently the corpus exercises only the
  clean path; single-anomaly fixtures for each error tag would round
  out coverage.
- `SUBLANG` table refinement. The current implementation models
  sublang values as language-independent, which is incorrect for
  multilingual edge cases (sublang `0x02` means UK English with
  primary English, but Swiss German with primary German). A flat
  LCID → BCP-47 mapping is the structural fix; deferred as a separate
  ticket since the current behaviour is correct for the common case.

---

# **v0.7.4.1 — Windows‑Compatible PE Detection Hotfix**

IOCX v0.7.4.1 removes the `python-magic` dependency, improves PE detection accuracy, and reduces IOCX’s attack surface.

## **Added**

- Pure‑Python file‑type detection for full cross‑platform portability
- Strict Windows‑compatible PE validation:
  - Require valid `e_lfanew` and `PE\0\0` signature
  - Reject MZ‑only, truncated, or malformed binaries as **UNKNOWN**
  - Prevent fallback to **TEXT** for invalid MZ files

---

## **Changed**

- Removed `python-magic` dependency; file detection is now implemented entirely in Python

---

# **v0.7.4 — Advanced Directory Parsing & Metadata Expansion**

IOCX v0.7.4 significantly expands static PE coverage with advanced directory parsing, extended metadata extraction, and deterministic structural validation. This release improves correctness across modern compiler outputs while preserving IOCX’s static‑only, zero execution design.

---

## **Added**

### **New RVA‑Graph Invariants**
- **DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA**
  Detects directories that simultaneously signal presence (non‑zero RVA) and absence (zero size).
  Implemented with primary‑error semantics to suppress downstream mapping noise.

- **DATA_DIRECTORY_RAW_MISMATCH**
  Flags directories whose RVA maps into a section’s virtual range but whose computed raw offset lies outside the section’s raw data.
  Includes a dedicated reason code and validator‑level consistency check.

- **Raw‑mapping safety guard**
  Prevents invalid raw‑offset calculations when sections contain no raw data.

### **New Adversarial Fixtures for Directory Invariants**
- `directory_zero_size_nonzero_rva.full.exe`
- `directory_raw_mismatch.full.exe`

### **Full Load Config Directory Parsing**
- GuardCF metadata
- Security cookie
- SEH table
- Compiler‑specific layout hints
- Deterministic error handling for malformed structures

### **Load Config Adversarial Fixtures**
- `load_config_cookie_too_small.full.exe`
- `load_config_malformed_size_too_small.full.exe`
- `load_config_malformed_truncated.full.exe`
- `load_config_malformed_cookie_in_overlay.full.exe`
- `load_config_malformed_cookie_invalid.full.exe`
- `load_config_malformed_guard_cf_inconsistent.full.exe`
- `load_config_malformed_seh_invalid.full.exe`
- `load_config_malformed_size_exceeds_section.full.exe`

---

## **99 Adversarial PE Fixtures for Structural & Parser‑Behaviour Testing**

### **Entrypoint Fixtures (000–009)**
Covers malformed `AddressOfEntryPoint` conditions:
- Zero/negative EP
- EP inside headers
- EP outside `SizeOfImage`
- EP unmapped to any section
- EP in non‑executable section
- EP spanning boundaries
- EP in overlay

**Outcome:** Entrypoint validator stable and deterministic across all malformed cases.

---

### **Section Table Fixtures (010–021)**
Covers structural correctness of section headers and RVA/raw mappings:
- Out‑of‑bounds RVA
- Out‑of‑bounds raw offset
- Overlapping sections
- Unsorted sections
- `VirtualSize < RawSize`
- Misaligned boundaries
- Section extends past `SizeOfImage`
- Section mapped inside headers

**Outcome:** All anomalies correctly identified; no false positives on valid baselines.

---

### **Optional Header Fixtures (022–033)**
Covers correctness of Optional Header fields:
- Invalid `SizeOfImage` / `SizeOfHeaders`
- Invalid `FileAlignment` / `SectionAlignment`
- Magic mismatch (PE32 vs PE32+)
- Invalid subsystem / version fields
- ImageBase misalignment
- `NumberOfRvaAndSizes` too small

**Outcome:** Optional‑header validator behaves consistently; malformed fields reliably detected.

---

### **Data Directory Fixtures (034–045)**
Covers adversarial manipulations of the Data Directory Table:
- Negative RVA / size
- Zero/zero directory (valid)
- Zero RVA with non‑zero size
- Zero size with non‑zero RVA
- Directory inside headers
- Directory out of `SizeOfImage`
- Directory in overlay
- Unmapped directory
- Directory spanning sections
- Overlapping directories

**Outcome:**
All malformed cases correctly trigger the **primary structural anomaly**
`optional_header_invalid_number_of_rva_and_sizes`.
Fixture 036 (zero/zero) produces no anomalies, confirming non‑aggressive behaviour.

---

### **Overall Result for Fixtures 000–045**
- **All 46 fixtures validated**
- **No crashes or inconsistent behaviour**
- **All anomalies match intended design**
- Entrypoint, section, optional‑header, and directory validators confirmed stable

---

## **Comprehensive Layer‑2 Load Config Fixtures**

A full suite of Load Config edge‑case binaries validating compiler differences, malformed structures, and ambiguous layouts:

- **Minimal MinGW Load Config** (undersized structure detection)
- **Cookie‑Only (Valid)** (minimum‑size compliance, RVA mapping, section writability)
- **Cookie‑Only (Too Small)** (strict minimum‑size enforcement)
- **Full MSVC Load Config** (SEH, GuardCF, cookie, full‑path validation)
- **Full Clang/LLVM Load Config** (GuardCF without SEH)
- **Large Padded Load Config** (oversized, schema‑unknown layouts)
- **SEH‑Only Load Config** (partial‑structure handling)

**Outcome:**
Validates RVA/VA correctness, section‑mapping rules, minimum‑size enforcement, GuardCF consistency, SEH bounds checking, and compiler‑specific structural differences.

---

## **Changed**

- Load Config validator surfaced new anomalies in contract tests:
  - Crypto Entropy Payload
  - Franken URL Domain IP
  - Malformed Domain / IP / URL
  - String Obfuscation Tricks
  - Invalid Optional Header (PE32 / PE32+)

- Internal schema now includes:
  - `number_of_rva_and_sizes`
  - `data_directories_raw`
  Supporting adversarial optional‑header edge cases.

- Optional‑header validator:
  - Now checks declared vs raw directory counts
  - FixtureSpec and emitter updated to support adversarial `NumberOfRvaAndSizes` mismatches
  - Raw vs declared count logic now fully enforced

---

## **Documentation**
- Updated RVA / Directory Anomalies table with new reason codes and behavioural notes
- Added **Design Decision: Why Only the Optional‑Header Validator Uses Raw Data Directories**

---

# v0.7.3 — Structural Correctness & Deterministic Heuristics
**Released: 2026‑05‑11**

## Added
- Comprehensive structural validation across all PE subsystems
- New checks for entrypoint mapping, section flags, RVA graph consistency, TLS callbacks, and certificate bounds
- Region‑specific entropy validation
- Deterministic structural anomaly surfacing in heuristics layer
- Extensive new structural and heuristic tests
- Snapshot tests ensuring deterministic output

## Changed
- Reworked entrypoint validator with correct RVA→file offset mapping
- Expanded section validator with overlap, ordering, and flag‑consistency checks
- Strengthened optional header validation (alignment, size fields, directory count)
- Hardened RVA graph validator (bounds, mapping, overlap)
- Improved TLS validator (range, callbacks, mapping)
- Improved signature validator (symmetry, bounds, type/revision checks)
- Refined entropy validator (low entropy, region entropy, uniformity)

## Fixed
- Conceptual inconsistencies around RVA vs file offsets
- Redundant or contradictory structural checks
- Missing structural anomalies in several validators
- Inconsistent or unclear ReasonCodes
- Edge‑case crashes on malformed or truncated binaries

## Removed
- No removals in this release

## Notes
- v0.7.3 remains strictly static-only
- No dynamic analysis, unpacking, emulation, or new dependencies introduced

---

# v0.7.2 — Dependency fix
**Released: 2026‑05‑01**

## Added
- Required `idna` dependency for punycode and Unicode domain handling
- No behavioural changes to extractors
- No schema changes
- Fully compatible with v0.7.1

---

# **v0.7.1 — Heuristics Engine Expansion & Structural Analysis Improvements**
**Released: 2026‑05‑01**

v0.7.1 delivers a major upgrade to IOCX’s **PE heuristics engine**, **extractor correctness**, and **adversarial‑input resilience**. This release introduces six new structural heuristics, broad extractor hardening, and a significantly expanded adversarial test suite — including **full adversarial coverage for every IOC category**.

---

# **Extractor Hardening**

This release strengthens multiple IOC extractors with improved correctness, boundary handling, and adversarial‑text resilience. Updates span the **bare domain**, **strict URL**, **crypto**, and **hash** extractors, plus improved **URL normalisation**.

## **Bare Domain Extractor**

### **Improvements**
- Expanded **TLD allow‑list** (e.g., `.ly`, `.gg`, `.sh`, `.app`, `.dev`, `.xyz`, `.online`) for broader real‑world coverage.
- Strengthened **BAD_TLD deny‑list** to prevent file extensions, config keys, and log fields from being misclassified as domains.
- Refined **boundary detection** to reduce false positives in noisy or punctuation‑heavy text.
- Added **punycode + IDN homoglyph analysis**, including Unicode decoding, script classification, and confusable‑character detection.
- Improved regex structure for **stability and predictable linear performance**, eliminating pathological backtracking cases.

### **Impact**
- Higher recall for legitimate domains across modern TLDs.
- Significant reduction in false positives from filepaths, dotted identifiers, and structured logs.
- Richer, homoglyph‑aware metadata for downstream analysis and phishing detection.

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
