# **v0.7.6 — Structural validator expansion: debug, relocations directories**
**Released: 2026‑08‑10**

## Added
- **Expanded static PE directory coverage.** Deterministic, pefile-independent
struct decoders for the following directories: **Relocations**,
**Certificate Table**, **Debug Directory**, and **TLS**.
- **Relocation parsing** — `IMAGE_BASE_RELOCATION` blocks with typed
entries (HIGHLOW, DIR64, …), block-size and word-alignment validation,
and per-entry target-RVA checks.
- **Certificate table parsing** — `WIN_CERTIFICATE` entries (revision,
type, length) read from raw file bytes, with an "offset must lie outside
the image" invariant. The embedded PKCS#7 blob is left opaque.
- **Debug directory parsing** — `IMAGE_DEBUG_DIRECTORY` entries with
deterministic CodeView PDB-path extraction (RSDS/NB10) and canonical
mixed-endian GUID formatting.
- **TLS parsing** — `IMAGE_TLS_DIRECTORY` (PE32/PE32+) with VA→RVA callback
resolution via `ImageBase`, bounded callback walking, and zero-length
raw-data handling.
- Structured, JSON-safe metadata for all new directories
(`relocation_struct`, `certificate_struct`, `debug_struct`, `tls_struct`).
- New deterministic reason codes: `certificate_table_malformed`,
`certificate_offset_inside_image`, `tls_directory_truncated`,
`tls_callback_rva_invalid`, plus the `relocation_*` and `debug_*`
families.

## Changed
- **Signature & TLS validators** now consume the new deterministic
`certificate_struct` / `tls_struct` from internal metadata instead of
pefile-derived data. All prior reason codes and checks are preserved.
- Structural validator dispatcher registers the new `relocations` and
`debug` validators; directory placement remains solely owned by the
RVA-graph validator to avoid double-counting.

## Fixed
- Corrected a latent VA/RVA unit mismatch when mapping TLS callback
pointers to sections.
- TLS: surface parser tombstones that were previously dropped
(`tls_image_base_unavailable`, `tls_callbacks_va_below_image_base`).
- TLS: a zero-length raw-data region accompanied by a valid callback array
no longer raises a false-positive `tls_zero_length_directory`.

## Notes
- Static-only and deterministic by design: no dynamic execution,
unpacking, emulation, ML, sandboxing, or network access.

---

# **v0.7.5 - Structural validator expansion**
**Released: 2026‑07‑01**

This release substantially expands IOCX's structural validator suite with four new parser/validator pairs (export tables, delay-load imports, VS_VERSIONINFO, and the resource directory's Type → Name → Language hierarchy), enriches public metadata with security-relevant Optional Header and per-resource fields, and adds 24 new structural reason codes across exports, resources, and delay-load. All new code lands with 100% line and branch coverage backed by real-binary verification.

## Added

### New structural validators

- **Export table parser and validator** (pe_exports, exports). Decodes the 40-byte IMAGE_EXPORT_DIRECTORY, EAT, ENPT, and EOT purely from bytes; emits ten new reason codes covering directory, name-pointer, and function-entry anomalies. Forwarder detection follows the PE-spec rule (address RVA within export directory range). Absence of an export directory is not treated as a defect.
- **Delay-load import parser and validator** (parser_delay_imports, validator_delay_imports). Decodes the 32-byte IMAGE_DELAY_IMPORT_DESCRIPTOR, INT, and IAT purely from bytes; emits eight new reason codes covering directory, descriptor, and entry anomalies. PE32+ vs PE32 thunk sizing determined once from OPTIONAL_HEADER.Magic; v1 vs v0 attribute mode captured explicitly rather than coerced; bound state detected by bound_iat_rva != 0. Absence of a delay-load directory is not treated as a defect.
- **VS_VERSIONINFO parser and validator** (pe_version_info, validator_version_info). Decodes the version-info envelope, VS_FIXEDFILEINFO, StringFileInfo, and VarFileInfo purely from bytes; emits four new reason codes covering header, FixedInfo, StringFileInfo, and VarFileInfo malformations. Leaf selection across multiple RT_VERSION entries is deterministic, sorted by (name_id, language_id). Absence of RT_VERSION is not treated as a defect.
- **Resource hierarchy enforcement.** Resource validator now tracks tree depth and enforces the PE spec's Type → Name → Language layering, emitting two new reason codes (RESOURCE_DIRECTORY_LANGUAGE_NOT_ID, RESOURCE_DATA_AT_INVALID_DEPTH).

### Reason codes added (24 total)

- **Resource hierarchy (2):** RESOURCE_DIRECTORY_LANGUAGE_NOT_ID, RESOURCE_DATA_AT_INVALID_DEPTH
- **VS_VERSIONINFO (4):** RESOURCE_VERSIONINFO_INVALID_HEADER, _INVALID_FIXEDINFO, _INVALID_STRINGFILEINFO, _INVALID_VARFILEINFO
- **Exports (10):** EXPORT_DIRECTORY_INVALID_HEADER, _OUT_OF_BOUNDS, EXPORT_TABLE_TRUNCATED, EXPORT_NAME_RVA_INVALID, _NOT_ASCII, _POINTER_TABLE_UNSORTED, _ORDINAL_INDEX_INVALID, EXPORT_ORDINAL_OUT_OF_RANGE, EXPORT_FUNCTION_RVA_INVALID, EXPORT_FORWARDER_MALFORMED
- **Delay-load (8):** DELAY_IMPORT_DIRECTORY_INVALID_HEADER, _OUT_OF_BOUNDS, DELAY_IMPORT_TABLE_TRUNCATED, DELAY_IMPORT_DESCRIPTOR_INVALID, DELAY_IMPORT_DLL_NAME_INVALID, _INT_IAT_MISMATCH, _ATTRIBUTES_LEGACY_VA_MODE, DELAY_IMPORT_ENTRY_INVALID

All new codes follow the established pattern: priority-resolved sub-reasons surfaced via details["reason"], with sub-table scoping via details["table"] where applicable.

### Public metadata enrichment

- **Optional Header fields.** New fields in the optional_header block: dll_characteristics (raw value), dll_characteristics_flags (decoded flag names sorted by bit position), dll_characteristics_unknown_bits (hex string for unrecognised bits), win32_version_value, loader_flags, stack_reserve_size, stack_commit_size, heap_reserve_size, heap_commit_size.
- **Header decoding.** New subsystem_name field in the header block, decoded from IMAGE_SUBSYSTEM_* (e.g., "WINDOWS_CUI"); returns null for unknown values. Raw subsystem integer unchanged. New machine_name field decoded from IMAGE_FILE_MACHINE_* (e.g., "AMD64", "I386", "ARM64"); the supporting MACHINE_NAMES table covers all 29 documented machine types.
- **Resource metadata.** The resources field now exposes a structured ResourceEntry per resource covering type, name, language, language_name, codepage, size, entropy, rva, raw_offset, and errors. Per-resource Shannon entropy is rounded to 4 decimal places. Output is sorted by (type, language, rva) for snapshot stability. Resources whose data bytes cannot be read are no longer silently dropped; they are emitted with errors populated (tags: size_invalid, rva_invalid, data_out_of_bounds, raw_offset_invalid).

### Schema typing

- New TypedDicts: ExportStruct, ExportDirectoryHeader, ExportFunctionEntry, ExportNamePointerEntry, DelayImportStruct, DelayImportDescriptor, DelayImportEntry, VersionInfoStruct and its sub-types (FixedFileInfo, StringFileInfo, StringTable, VarFileInfo, VarEntry, Translation).
- InternalMetadata.resources_struct is now Optional[ResourcesStruct] with a fully-typed ResourceEntry shape replacing List[Any]. InternalMetadata.export_struct, delay_import_struct, and version_info_struct are typed as Optional of their respective structs.
- New constants module iocx.parsers.pe_constants houses SUBSYSTEM_NAMES, MACHINE_NAMES, DLL_CHARACTERISTICS_FLAGS, and the derived DLL_CHARACTERISTICS_KNOWN_MASK.

## Changed

### Validator dispatcher

Three new validators registered in the structural validator chain, in order:

```
validate_resources → validate_version_info → validate_exports → validate_delay_imports → validate_entropy
```

This completes the resource and import/export structural validator clusters ahead of the entropy/derived layer.

### Parser robustness

- **Guarded RVA→offset conversion.** pe.get_offset_from_rva calls are now guarded against pefile.PEFormatError and AttributeError. A corrupt RVA produces a -1 sentinel in raw_offset rather than propagating the exception. The validator's existing data_raw < 0 arm maps this to the existing RESOURCE_DATA_OUT_OF_BOUNDS reason code; no new code introduced.
- **Resource entropy now computed over the correct byte range.** Previously sliced get_memory_mapped_image() with the raw file offset; now correctly uses the RVA. Caught before snapshot stamping; entropy values match the previous release's behaviour for all existing fixtures.

### Schema and decoding semantics

- **ResourceEntry schema expanded.** Fields are now total=False Optional to accommodate per-entry computation failures. New fields: codepage, errors. The name, rva, and raw_offset fields are now populated where they were previously declared but absent from output.
- **_decode_langid returns None for undecodable LANGIDs** (previously returned the magic string "unknown"). The early-return guard if langid < 0x0400 was removed; it was rejecting valid neutral-sublang LANGIDs (LANGID 0x0001 now correctly decodes as "ar" for Arabic).
- **Optional Header missing-field convention.** New Optional Header fields use None as the default value when pefile cannot extract the field, distinct from 0 which indicates the binary's actual value. This is a deliberate semantic split for security-relevant fields where "missing" and "zero" carry different meaning. Existing Optional Header fields retain their default-to-zero behaviour for backward compatibility.

### Extended analyser refactor

- **analyse_extended cleaned up.** Removed duplicated _SUBSYSTEM_MAP and _MACHINE_MAP lookup tables now that decoded names come from the parser layer. The legacy subsystem_human and machine_human fields are removed from extended metadata output. Resource entropy summary statistics (entropy_min, entropy_max, entropy_avg) now compute over only entries with computed entropy values, excluding entropy: None entries.

## Fixed

- **Resource validator no longer silently returns** when a directory's own RVA falls outside .rsrc. Previously suppressed any reporting for malformed directory placement.

## Documentation

- **Reason codes reference** extended with new top-level sections for Resource Hierarchy Anomalies, Resource Version-Info Anomalies, Export Anomalies, and Delay-Load Import Anomalies, each with dedicated sub-reason taxonomy sections documenting the details["reason"] and details["table"] contracts.
- **Validator documentation** gained sections 2.5 (VS_VERSIONINFO), 2.6 (exports), and 2.7 (delay-load imports), each with explicit determinism rationale. Section 2.7 frames the three spec-interpretation questions (v0 vs v1 attribute mode, INT/IAT mirror vs bound assumption, declared-size vs walk-to-terminator) that produce cross-tool divergence.
- **Schema reference** documents the new Optional Header fields (including the dll_characteristics_unknown_bits role in preserving complete information about non-decoded bits) and the mixed-default convention with rationale.
- **analyse_extended module purpose** documented inline via module docstring clarifying that the module performs shape conversion and derived-statistics computation only, not new information extraction.
- **_decode_langid semantics** documented inline (primary language and sublang decomposition, fallback to default region, fallback to primary-language-only, fallback to None).

## Internal

- **100% line and branch coverage** on all new modules: pe_version_info, validator_version_info, pe_exports, exports, parser_delay_imports, validator_delay_imports, _parse_optional_header, _parse_header, pe_constants, and resource validator additions.
- **Defensive-path coverage** via monkeypatched struct.error injection across all four parsers. Narrow-except negative tests confirm parser exception handling does not silently swallow exceptions outside the documented catch list.
- **One # pragma: no cover** applied to a defensive return in the exports validator's _first_unsorted_index helper, documented inline as unreachable from the caller.
- **End-to-end binary verification.** Delay-load parser cross-checked against mspaint.exe via dumpbin /imports: 107 imports decoded from gdiplus.dll's delay-load directory with byte-exact agreement on DLL name, hint values, IAT addresses, ordering, and bound state across both tools.

**Total: ~650 new tests bringing the suite to 1370 tests.**

## Compatibility

### No remapping of existing reason codes

Existing fixture expected outputs are unchanged for binaries that don't exercise the new pathways.

### Snapshot refresh required

The following changes will produce diffs in fixture expected outputs and require a coordinated snapshot refresh:

- Resource fixtures gain new ResourceEntry keys (codepage, errors, name, rva, raw_offset); resources with errors now appear where they were previously silently dropped.
- language_name no longer returns "unknown"; consumers checking language_name == "unknown" must update to language_name is None.
- Every fixture with an optional header gains new Optional Header keys (dll_characteristics, _flags, _unknown_bits, win32_version_value, loader_flags, stack/heap sizing fields).
- header block gains subsystem_name and machine_name keys.
- Extended metadata no longer emits subsystem_human and machine_human; consumers should use subsystem_name and machine_name (the parser layer is now the single source of truth for both).

All refreshes are mechanical via the existing fixture regeneration tooling.

### No public IOC schema changes in this release

export_struct and delay_import_struct are exposed only in internal metadata by design - they feed validators, not consumer schema. Public IOC schema exposure for version-info is deferred to a coordinated future release with corresponding fixture corpus refresh.

## Known scheduled work

- **Single-anomaly fixtures** targeting the new reason codes across resources, version-info, exports, and delay-load (~25 fixtures planned). Includes negative-control fixtures (exp_forwarder_to_ordinal_valid, delay_well_formed_bound_modern, delay_well_formed_unbound_with_ordinal_import) demonstrating that validators do not false-positive on healthy spec-valid inputs.
- **Public IOC schema promotion** of version_info_struct planned for a future release with corpus refresh. Contains consumer-facing metadata (CompanyName, ProductVersion, OriginalFilename, FileDescription) with established IOC value.
- **Internal-only structural data.** export_struct, delay_import_struct, and Load Config metadata remain internal by design — they exist to feed validators and heuristics, not the public IOC schema. Consumers needing structural information about these directories should rely on the validators' reason codes and (for exports/delay-load) the existing consumer-facing metadata fields.
- **SUBLANG table refinement.** The current implementation models sublang values as language-independent, which is incorrect for multilingual edge cases (sublang 0x02 means UK English with primary English, but Swiss German with primary German). A flat LCID → BCP-47 mapping is the structural fix; deferred since current behaviour is correct for the common case.
- **TLS Directory parser and validator.** Originally deferred from this release; planned for the next release.
- **Cross-tool divergence study** using the new fixtures. Delay-load is a particularly strong divergence candidate because the three identified spec-interpretation questions are known to produce inconsistent output across pefile, LIEF, Ghidra, and IDA. Tracked separately as a methodology contribution opportunity.
- **Filed work items**:
   - pefile_usage_policy.md documenting the deterministic-subset usage pattern.
   - PE_CFG_DECLARATION_INCONSISTENT heuristic (DllCharacteristics ↔ Load Config GuardFlags cross-validator consistency).
   - PE_FIELDS_IMPLAUSIBLE heuristic for "cannot exist in wild" binaries.
   - PE_DLL_CHARACTERISTICS_INCONSISTENT heuristic for intra-field flag dependency violations (e.g., HIGH_ENTROPY_VA without DYNAMIC_BASE).
   - Existing-field default migration (the 0 vs None inconsistency in OptionalHeaderInfo).

---

# **v0.7.4.1 — Windows‑Compatible PE Detection Hotfix**
**Released: 2026‑05‑28**

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
**Released: 2026‑05‑26**

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
