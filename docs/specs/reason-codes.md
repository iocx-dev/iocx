# **PE Structural Reason Codes**

> **Truncation detail keys are not uniform.** `EXPORT_TABLE_TRUNCATED`,
> `DELAY_IMPORT_TABLE_TRUNCATED`, `IMPORT_TABLE_TRUNCATED` and `EXCEPTION_TABLE_TRUNCATED`
> name the affected sub-table in a **`table`** key. `DEBUG_TABLE_TRUNCATED`,
> `RELOCATION_TABLE_TRUNCATED` and `TLS_DIRECTORY_TRUNCATED` use **`region`**
> instead. Both are stable; consumers handling truncation generically must
> read either.

> **On the `sub_reason` field.** The key is deliberately not named `reason`:
> the heuristics layer emits the parent code under `reason`, and a details key
> of the same name would overwrite it. Sub-reasons are priority-resolved where
> noted — a single entry carrying several tags reports exactly one, the first
> in the documented order.

## **SECTION ANOMALIES**

| Reason Code | What Triggers It | Example Malformed Pattern | Scope |
|------------|------------------|---------------------------|--------|
| **SECTION_RWX** | Section has both `MEM_EXECUTE` and `MEM_WRITE` | `.text` marked executable + writable | Per‑section |
| **SECTION_NON_EXECUTABLE_CODE_LIKE** | `CNT_CODE` flag set but section not executable | `.text` with `CNT_CODE` but missing `MEM_EXECUTE` | Per‑section |
| **SECTION_CODELIKE_NAME_NOT_EXECUTABLE** | Name looks like code (`.text`, `code`, etc.) but section not executable | `.text` with only `READ` | Per‑section |
| **SECTION_NAME_NON_ASCII** | Section name contains non‑ASCII bytes | Name = `"\xFF\xFE\xFA\x00"` | Per‑section |
| **SECTION_NAME_EMPTY_OR_PADDING** | Name is empty or only NUL/padding | Name = `"\x00\x00\x00\x00\x00\x00\x00\x00"` | Per‑section |
| **SECTION_IMPOSSIBLE_FLAGS** | Section is discardable + executable + writable | `.text` with `MEM_DISCARDABLE | MEM_EXECUTE | MEM_WRITE` | Per‑section |
| **SECTION_RAW_MISALIGNED** | `PointerToRawData % FileAlignment != 0` | Raw offset = 291, FileAlignment = 512 | Per‑section |
| **SECTION_RAW_OVERLAP** | Raw ranges of two sections intersect | `.text` raw `[0x200–0x800)` overlaps `.rdata` raw `[0x300–0x900)` | Global (pairwise) |
| **SECTION_OVERLAP** | Virtual address ranges intersect | `.text` VA `[0x1000–0x1800)` overlaps `.rdata` VA `[0x1400–0x1C00)` | Global (pairwise) |
| **SECTION_OVERLAPS_HEADERS** | `PointerToRawData < SizeOfHeaders` | `.bss` raw offset = 0, `SizeOfHeaders = 1536` | Per‑section |
| **SECTION_OUT_OF_ORDER_RAW** | Raw addresses not sorted ascending | Raw list = `[1536, 8192, 0, 19456...]` | Global |
| **SECTION_OUT_OF_ORDER_VIRTUAL** | Virtual addresses not sorted ascending | VA list = `[0x2000, 0x1000]` | Global |
| **SECTION_ZERO_LENGTH** | `virtual_size == 0` AND `raw_size == 0` | `.zero` section with no memory or file footprint | Per‑section |
| **SECTION_DISCARDABLE_CODE** | Section is executable AND discardable | `.text` with `MEM_EXECUTE | MEM_DISCARDABLE` | Per‑section |
| **SECTION_FLAGS_INCONSISTENT** | Contradictory flags: code/write/exec without read | `.text` with `EXECUTE` but missing `READ` | Per‑section |

## SECTION SUB‑REASONS

### SECTION_FLAGS_INCONSISTENT

Emitted once per violated combination, so one section may raise several:

| Sub‑reason | Meaning |
|------------|---------|
| code_without_read | `CNT_CODE` set but `MEM_READ` absent |
| write_without_read | `MEM_WRITE` set but `MEM_READ` absent |
| exec_without_read | `MEM_EXECUTE` set but `MEM_READ` absent |

---

## **ENTRYPOINT ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **ENTRYPOINT_OUT_OF_BOUNDS** | EP does not map to any section | EP = `0x90000000`, SizeOfImage = 512 | Per‑file |
| **ENTRYPOINT_SECTION_NOT_EXECUTABLE** | EP maps to non‑executable section | EP inside `.rdata` | Per‑file |
| **ENTRYPOINT_IN_TRUNCATED_REGION** | EP beyond section’s virtual size | EP = `VA + VirtualSize + 1` | Per‑file |
| **ENTRYPOINT_IN_OVERLAY** | EP maps to file offset ≥ overlay offset | EP raw offset = 0x5000, overlay = 0x4000 | Per‑file |
| **ENTRYPOINT_ZERO_OR_NEGATIVE** | EP ≤ 0 | EP = 0 | Per‑file |
| **ENTRYPOINT_IN_HEADERS** | EP < SizeOfHeaders | EP = 0x100, SizeOfHeaders = 0x400 | Per‑file |
| **ENTRYPOINT_IN_NON_CODE_SECTION** | EP inside `.rsrc`, `.reloc`, or non‑code section | EP inside `.rsrc` | Per‑file |
| **ENTRYPOINT_IN_DISCARDABLE_SECTION** | EP inside discardable section | EP inside `.upx0` with discardable flag | Per‑file |

## ENTRYPOINT SUB‑REASONS

### ENTRYPOINT_IN_TRUNCATED_REGION

Mutually exclusive — the zero-length case takes precedence:

| Sub‑reason | Meaning |
|------------|---------|
| zero_length_section | The mapped section has `VirtualSize == 0` |
| beyond_virtual_size | EP lies at or past `VirtualAddress + VirtualSize` |

---

## **OPTIONAL HEADER ANOMALIES**

| Reason Code | What Triggers It | Example Malformed Pattern | Scope |
|------------|------------------|---------------------------|--------|
| **OPTIONAL_HEADER_INCONSISTENT_SIZE** | `max(section_end)` exceeds `SizeOfImage` | `.rsrc` ends at `0x3800`, `SizeOfImage = 0x2000` | Per‑file |
| **OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS** | `SizeOfHeaders` misaligned OR smaller than required header size | `SizeOfHeaders = 2048`, `FileAlignment = 16384` | Per‑file |
| **OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT** | `SectionAlignment < FileAlignment` OR not power‑of‑two | `SectionAlignment = 4096`, `FileAlignment = 16384` | Per‑file |
| **OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT** | Not power‑of‑two OR outside 512–64K range | `FileAlignment = 300` | Per‑file |
| **OPTIONAL_HEADER_SIZE_FIELDS_INCONSISTENT** | SizeOfCode / SizeOfInit / SizeOfUninit smaller than section totals | `.text` raw = 0x600, `SizeOfCode = 0x200` | Per‑file |
| **OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED** | `ImageBase` not 64K aligned | `ImageBase = 0x12345` | Per‑file |
| **OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES** | `NumDirs` < actual directories OR > 16 | `NumDirs = 1`, actual = 3 | Per‑file |
| **OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED** | `SizeOfImage % SectionAlignment != 0` | `SizeOfImage = 512`, `SectionAlignment = 4096` | Per‑file |

## OPTIONAL HEADER SUB‑REASONS

### OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT

| Sub‑reason | Meaning |
|------------|---------|
| not_power_of_two | `SectionAlignment` is not a power of two |
| *(none)* | `SectionAlignment < FileAlignment` — this branch carries no sub‑reason and is identified by the presence of a `file_alignment` key in details |

### OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT

Both checks are independent, so a single value may raise both:

| Sub‑reason | Meaning |
|------------|---------|
| not_power_of_two | `FileAlignment` is not a power of two |
| out_of_range | `FileAlignment` outside the recommended 512–65536 range |

### Codes distinguished by detail keys rather than sub‑reasons

Two optional‑header codes have multiple emission sites with no `sub_reason`.
They are separable by a discriminating key:

| Reason Code | Branch | Discriminating key |
|-------------|--------|--------------------|
| OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS | misaligned to FileAlignment | `file_alignment` |
| OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS | below required minimum | `required_minimum` |
| OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES | count outside 0–16 | *(absent)* |
| OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES | count below actual directories | `actual_directories` |

---

## **RVA / DIRECTORY ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **DATA_DIRECTORY_INVALID_RANGE** | Directory has negative RVA or negative Size | RVA = –1, Size = 128 | Per‑directory |
| **DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED** | Directory is empty *(rva=0,size=0)* but this directory type is required to be non‑empty (currently none) | Import directory empty (if required) | Per‑directory |
| **DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE** | Directory claims to exist but points to RVA 0 | Resource RVA = 0, Size = 256 | Per‑directory *(primary error, all others suppressed)* |
| **DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA** | Directory has Size=0 but a non‑zero RVA, meaning “absent” and “present” simultaneously | RVA = 0x2000, Size = 0 | Per‑directory *(primary error, mapping suppressed)* |
| **DATA_DIRECTORY_IN_HEADERS** | Directory RVA lies inside the PE headers region | RVA = 0x100, SizeOfHeaders = 0x200 | Per‑directory |
| **DATA_DIRECTORY_OUT_OF_RANGE** | Directory extends beyond `SizeOfImage` | RVA = 0x5000, Size = 0x2000, SizeOfImage = 0x4000 | Per‑directory *(primary error, mapping suppressed)* |
| **DATA_DIRECTORY_IN_OVERLAY** | Directory maps to a raw offset ≥ overlay start | RVA maps to raw offset 0x6000, overlay starts at 0x5800 | Per‑directory |
| **DATA_DIRECTORY_RAW_MISMATCH** | Directory RVA maps into a section’s virtual range but the computed raw offset lies outside that section’s raw data | RVA=0x2500 maps to .text, but raw offset=0xC00 is outside .text raw range | Per‑directory |
| **DATA_DIRECTORY_NOT_MAPPED_TO_SECTION** | Directory is in range but does not fall inside any section | RVA = 0x9000, Size = 0x200, no section covers it | Per‑directory *(suppressed for empty, zero‑RVA, zero‑size, out‑of‑range and zero‑length‑section directories)* |
| **DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS** | Directory range overlaps more than one section | RVA = 0x1800, Size = 0x1000 spans .text → .rdata | Per‑directory |
| **DATA_DIRECTORY_OVERLAP** | Two directories’ RVA ranges overlap | Import and IAT overlap | Global |

> Prior to the `raw_offset` guard fix, `DATA_DIRECTORY_NOT_MAPPED_TO_SECTION` was additionally suppressed for any directory in a file carrying an overlay, because the raw-mapping guard skipped the section-mapping checks entirely. Files analysed before that fix may under-report it.

---

## **TLS ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **TLS_CALLBACK_OUTSIDE_RANGE** | Callback RVA not within the TLS directory’s `(start, end)` range | Callback = `0x5000`, TLS range = `0x4000–0x4100` | Per‑file |
| **TLS_MULTIPLE_DIRECTORIES** | More than one TLS directory is present in the PE | Two `tls_directory` entries in `extended` | Per‑file |
| **TLS_INVALID_RANGE** | TLS directory has `start >= end` (structurally impossible). The parser independently records `tls_raw_data_end_before_start` in its errors list and sets `raw_data_size` to `None` for this case; the validator derives the finding from the VA fields directly rather than from that tag, so the two never double-count. | Start = `0x6000`, End = `0x6000` | Per‑file |
| **TLS_ZERO_LENGTH_DIRECTORY** | TLS directory exists but `start == end` (zero‑length region) | Start = `0x7000`, End = `0x7000` | Per‑file |
| **TLS_CALLBACKS_MISSING** | TLS directory is non‑empty but callback pointer is `0` | Start = `0x4000`, End = `0x4100`, Callbacks = `0` | Per‑file |
| **TLS_CALLBACK_NOT_MAPPED_TO_SECTION** | Callback RVA does not fall inside any section’s VA range | Callback = `0x90000000` (no section covers it) | Per‑file |
| **TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION** | Callback RVA maps to a section lacking `IMAGE_SCN_MEM_EXECUTE` | Callback in `.data` or `.rdata` | Per‑file |
| **TLS_CALLBACK_IN_HEADERS** | Callback RVA falls inside the PE headers (`< SizeOfHeaders`) | Callback = `0x200`, SizeOfHeaders = `0x600` | Per‑file |
| **TLS_CALLBACK_IN_OVERLAY** | Callback RVA maps to a raw offset beyond the last section (overlay) | Raw offset = `0x1F000`, overlay starts at `0x1E000` | Per‑file |
| **TLS_CALLBACK_ARRAY_NOT_TERMINATED** *(optional future rule)* | Callback array exists but is not 0‑terminated | Callback list ends with non‑zero RVA | Per‑file |
| **TLS_DIRECTORY_TRUNCATED** *(v0.7.6)* | `pe_tls` struct decoder failed: the IMAGE_TLS_DIRECTORY header could not be read, or the callback array was truncated or looping | Header short read, or callback walk hit the 4096 hard limit with no NULL terminator | Per‑file |
| **TLS_CALLBACK_RVA_INVALID** *(v0.7.6)* | A resolved callback target (`AddressOfCallBacks − ImageBase`) cannot form a valid RVA or does not map to any section | Callback VA yielding a negative RVA, or an RVA covered by no section | Per‑file |

## TLS SUB‑REASONS

### TLS_DIRECTORY_TRUNCATED

| Sub‑reason | Meaning |
|------------|---------|
| header_decode | The fixed IMAGE_TLS_DIRECTORY could not be read or unpacked; unrecoverable, all later checks are skipped. The `errors` key lists the parser tags that triggered it |
| callback_array | A parser truncation tag surfaced while walking the callback array (the `region` key names the tag) |

#### `header_decode` — contributing parser tags

Listed in the issue's `errors` key. Any one of these short-circuits every
later TLS check:

| Parser tag | Meaning |
|------------|---------|
| tls_directory_read_failed | `pe.get_data` raised when reading the fixed struct |
| tls_directory_truncated | The read returned fewer than the full struct size (24 bytes PE32 / 40 bytes PE32+) |
| tls_directory_unpack_failed | `struct.unpack` failed on the struct bytes (defensive; unreachable past the length guard) |

#### `callback_array` — `region` values

One issue is emitted per tag, so a single directory may raise several:

| region value | Meaning |
|--------------|---------|
| tls_callbacks_read_failed | `pe.get_data` raised while reading a callback slot |
| tls_callbacks_truncated | A callback slot returned fewer than the pointer width (4 bytes PE32 / 8 bytes PE32+) |
| tls_callbacks_unpack_failed | `struct.unpack` failed on a slot (defensive; unreachable past the length guard) |
| tls_callbacks_max_exceeded | The walk hit the parser's hard limit (4096 callbacks) without finding a NULL terminator |

### TLS_CALLBACK_RVA_INVALID

Parser resolution tombstones (callback array unresolvable, `callbacks = []`):

| Sub‑reason | Meaning |
|------------|---------|
| tls_image_base_unavailable | ImageBase unavailable, so VA → RVA conversion is impossible |
| tls_callbacks_va_below_image_base | `AddressOfCallBacks` lies below ImageBase |

Per-target failures (one issue per target, capped at 16; the true count is
always in `invalid_callback_count`):

| Sub‑reason | Meaning |
|------------|---------|
| image_base_unavailable | Callbacks were resolved but ImageBase is not an int |
| below_image_base | A callback VA lies below ImageBase, yielding a negative RVA |
| not_mapped | A resolved callback RVA falls inside no section |

Emission is capped at 16 per-target issues; `invalid_callback_count` always
carries the true total. The two tombstone sub-reasons above are emitted at
most once each and are mutually exclusive with the per-target list, since the
parser returns `callbacks = []` in both cases.

---

## **SIGNATURE ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **SIGNATURE_FLAG_SET_BUT_NO_METADATA** | `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` set but no WIN_CERTIFICATE metadata present | Flag = 1, `signatures = []` | Per‑file |
| **SIGNATURE_PRESENT_BUT_FLAG_NOT_SET** | Certificate metadata exists but the integrity flag is not set | `signatures = [ … ]`, flag = 0 | Per‑file |
| **SIGNATURE_MULTIPLE_CERTIFICATES** | More than one WIN_CERTIFICATE structure present | Two or more entries in `signatures` | Per‑file |
| **SIGNATURE_INVALID_LENGTH** | `dwLength` smaller than the WIN_CERTIFICATE header (8 bytes) or otherwise nonsensical | `dwLength = 4` | Per‑certificate |
| **SIGNATURE_INVALID_REVISION** | `wRevision` not equal to 0x0100 or 0x0200 | `wRevision = 0x9999` | Per‑certificate |
| **SIGNATURE_INVALID_TYPE** | `wCertificateType` not X.509 (1) or PKCS#7 (2) | `certificate_type = 0x1234` | Per‑certificate |
| **SIGNATURE_OUT_OF_FILE_BOUNDS** | Certificate offset + size exceeds file size or begins before 0 | Offset = 0x200000, FileSize = 0x180000 | Per‑certificate |
| **SIGNATURE_OVERLAPS_OTHER_DATA** | Certificate overlaps a section, overlay, or other critical region | Certificate at raw 0x4000 overlaps `.text` | Per‑certificate |

---

## CERTIFICATE TABLE ANOMALIES

*Added in v0.7.6. Raw structural truth from the `pe_certificates` struct-level decoder, which walks the WIN_CERTIFICATE array from the file bytes. `DATA_DIRECTORY[4].VirtualAddress` is treated as a **file offset**, not an RVA — the certificate table is appended to the file and never mapped into the image. Placement/overlap has a single owner here to avoid double-counting with the RVA-graph backbone; the signature symmetry checks above interpret trust facts on top.*

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **CERTIFICATE_OFFSET_INSIDE_IMAGE** | The certificate table's file offset falls **before** the on-disk end of any section (`offset < image_raw_end`), i.e. it is not genuinely appended after the mapped image | Table offset = 0x3000, but `.rsrc` raw data ends at 0x5000 | Per‑file |
| **CERTIFICATE_TABLE_MALFORMED** | Top-level decode failure, or a WIN_CERTIFICATE entry surfaced a truncation tag (`sub_reason: "truncation"`) — e.g. `dwLength` runs past the file end, or the 8-byte header could not be read on the QWORD entry alignment | `dwLength` claims 0x900 bytes but only 0x40 remain in the file | Per‑file / Per‑certificate |

### CERTIFICATE_TABLE_MALFORMED sub‑reasons

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not decode the security directory at all; short-circuits before every other signature check |
| truncation | A WIN_CERTIFICATE entry surfaced a truncation tag (the `region` key names it) |

---

## **RESOURCE ANOMALIES**

### **Resource Directory Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_DIRECTORY_OUT_OF_BOUNDS** | A resource directory's `rva + size` does not lie wholly inside the `.rsrc` section. Two cases reach this: the **root** directory lies outside `.rsrc` (`depth` = 0), or a **subdirectory** starts inside `.rsrc` but its extent overflows the end (`depth` ≥ 1). A subdirectory lying wholly outside is reported by the parent as `RESOURCE_ENTRY_OUT_OF_BOUNDS` instead, so the two never double-count. `SizeOfImage` is not consulted — `.rsrc` bounds are authoritative here | Root directory RVA = `0x90000000` while `.rsrc` spans `0x1000–0x3000`; or a Name directory at `0x2FF8` with size 24 | Per‑directory |
| **RESOURCE_DIRECTORY_LOOP** | Recursive directory traversal detects a cycle (malformed or malicious resource tree) | Directory A → B → A | Per‑file |
| **RESOURCE_DIRECTORY_ZERO_LENGTH** (*reserved, not emitted*) | A resource directory exists but has zero length or no valid entries | RVA = `0x3000`, size = `0` | Per‑file |

### Resource Hierarchy Anomalies
| Reason Code |	What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **RESOURCE_DIRECTORY_LANGUAGE_NOT_ID** | A depth‑2 directory (Language layer) contains a named entry instead of an integer LCID, violating the Type → Name → Language hierarchy | Language entry keyed by "EN-US" instead of LCID 0x0409 | Per‑file
| **RESOURCE_DATA_AT_INVALID_DEPTH** | A data leaf appears at depth 0 (Type) or depth 1 (Name) instead of depth 2 (Language), skipping required hierarchy layers | Root Type directory contains a direct data leaf with no Name/Language subdirectories | Per‑file

### **Resource Entry / Data Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_ENTRY_OUT_OF_BOUNDS** | A resource directory entry points to a **subdirectory** whose RVA lies outside the `.rsrc` section. Out-of-bounds *data* entries are reported as `RESOURCE_DATA_OUT_OF_BOUNDS`, not here. The target's own size is not considered at this point — a subdirectory that starts inside `.rsrc` but overflows the end is caught by `RESOURCE_DIRECTORY_OUT_OF_BOUNDS` when it is descended into | Type directory entry points to a Name directory at RVA `0x80000000` | Per‑file |
| **RESOURCE_DATA_OUT_OF_BOUNDS** | Resource data block lies outside the file or outside the `.rsrc` section | Data offset = `0x1F0000`, file size = `0x1E0000` | Per‑file |
| **RESOURCE_DATA_OVERLAPS_OTHER_DATA** | A resource data blob spans the overlay start, or its raw or virtual extent intersects a section other than `.rsrc`. Blob-versus-blob comparison is **not** performed | Data at raw `0x2000–0x2400` intersects `.text` raw range | Per-file *(one issue per check; the raw-overlap and VA-overlap loops each stop at the first intersecting section, so a blob crossing several sections reports once per check, not once per section)* |

### Resource Version‑Info Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **RESOURCE_VERSIONINFO_INVALID_HEADER** | The VS_VERSIONINFO envelope is malformed: placement outside `.rsrc`, `szKey` not equal to "VS_VERSION_INFO", or `wLength` inconsistent with the buffer size | szKey = "VS_VERSION_BAD" instead of "VS_VERSION_INFO" | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_FIXEDINFO** | The embedded VS_FIXEDFILEINFO has an incorrect `dwSignature` (expected `0xFEEF04BD`) or `dwStrucVersion` (expected `0x00010000`), or fails to parse | dwSignature = `0xDEADBEEF` instead of `0xFEEF04BD` | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO** | A StringFileInfo, StringTable, or String child is malformed: invalid length field, non‑hex lang_codepage key, or truncated string entry	StringTable | key = "ENGLISHX" instead of 8‑hex‑char <langID><codepage> form | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_VARFILEINFO** | A VarFileInfo or Var child is malformed, or the Translation array's length is not a DWORD multiple	Var. | wValueLength = 6 (not divisible by 4) for a Translation array | Per‑file

*Note: absence of an RT_VERSION resource is not treated as a structural anomaly — many legitimate binary types (kernel drivers, MSI helpers, cross‑compiled artefacts) omit version‑info entirely.*

### RESOURCE_VERSIONINFO_INVALID_HEADER sub‑reasons

| Sub‑reason | Meaning |
|------------|---------|
| placement | The VS_VERSIONINFO blob does not lie wholly inside `.rsrc` |
| undecoded | The parser could not decode the envelope; short-circuits the FIXEDINFO / STRINGFILEINFO / VARFILEINFO checks |
| szkey_mismatch | `szKey` is not "VS_VERSION_INFO" |
| length_inconsistent | `wLength` disagrees with the buffer size |

### RESOURCE_VERSIONINFO_INVALID_FIXEDINFO sub‑reasons

| Sub‑reason | Meaning |
|------------|---------|
| parse_failed | VS_FIXEDFILEINFO is absent AND the parser recorded a `fixed_file_info*` error. A legitimate omission (`wValueLength == 0`) is not flagged |
| signature | `dwSignature` is not `0xFEEF04BD` |
| struct_version | `dwStrucVersion` is not `0x00010000` |

`RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO` and
`RESOURCE_VERSIONINFO_INVALID_VARFILEINFO` carry no sub‑reason; the parser's
tags are passed through verbatim in an `errors` list.

### **Resource String‑Table Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_STRING_TABLE_CORRUPT** | String table length, offsets, or UTF‑16 entries are malformed or out of bounds | String count = 32 but table only contains 10 entries | Per‑file |
| **RESOURCE_STRING_TABLE_UNREADABLE** | The RT_STRING traversal raised before completing, so the string-table list is empty or partial and its absence carries no meaning | Malformed Name or Language directory beneath RT_STRING | Per‑file |

---

## **ENTROPY ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **ENTROPY_HIGH_SECTION** | Section entropy ≥ 7.5 and size ≥ 1 KB | `.text` entropy = 7.9 | Per‑section |
| **ENTROPY_HIGH_OVERLAY** | Overlay entropy ≥ 7.5 and size ≥ 1 KB | Overlay entropy = 7.8 | Per‑file |
| **ENTROPY_UNIFORM_ACROSS_SECTIONS** | Mean entropy ≥ 7.5 **and** standard deviation ≤ 0.15, computed across sections whose raw size is ≥ 1 KB. Requires at least two such sections; smaller sections are excluded from the sample and can neither trigger nor prevent the finding. A single low-entropy section drags the mean below the threshold, so the check short-circuits before variance is considered | Mean = 7.7, stddev = 0.05 | Per‑file |
| **ENTROPY_VERY_LOW_SECTION** | Section entropy ≤ 0.2 **and** raw size ≥ 16 KB. The size floor is deliberately far higher than the 1 KB used by the high-entropy checks, to avoid flagging ordinary small padding sections | `.data` entropy = 0.03 | Per‑section |
| **ENTROPY_HIGH_RESOURCES** | Resource directory entropy ≥ 7.5 and region size ≥ 1 KB | `.rsrc` entropy = 7.9 | Per‑region |
| **ENTROPY_HIGH_RELOCATIONS** | Relocation table entropy ≥ 7.5 and region size ≥ 1 KB | `.reloc` entropy = 7.8 | Per‑region |
| **ENTROPY_HIGH_IMPORTS** | Import table entropy ≥ 7.5 and region size ≥ 1 KB | Import blob entropy = 7.7 | Per‑region |
| **ENTROPY_HIGH_TLS** | TLS directory entropy ≥ 7.5 and region size ≥ 1 KB | TLS entropy = 7.9 | Per‑region |
| **ENTROPY_HIGH_CERTIFICATE** | Certificate blob entropy ≥ 7.5 and region size ≥ 1 KB | WIN_CERTIFICATE entropy = 7.8 | Per‑region |

---

## **LOAD CONFIG DIRECTORY ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **LOAD_CONFIG_TOO_SMALL** | Declared Load Config size is smaller than the architecture‑required minimum (0x48 for PE32, 0x70 for PE32+) | PE32+ Load Config Size = 0x40 | Per‑directory *(primary error, parsing suppressed)* |
| **LOAD_CONFIG_TRUNCATED** | Raw data ends before the declared Load Config structure size; parser cannot read all required fields | Directory Size = 0x70 but only 0x30 bytes available in section | Per‑directory |
| **LOAD_CONFIG_GUARD_CF_INCONSISTENT** | Guard CF metadata fields are partially zero and partially non‑zero; invalid hybrid state | GuardCFCheckFunctionPointer = 0x1000, GuardCFFunctionCount = 0 | Per‑directory |
| **LOAD_CONFIG_COOKIE_INVALID** | Security cookie RVA does not map to a valid writable section, or maps outside image bounds | Cookie RVA = 0x9000, no section covers it | Per‑directory |
| **LOAD_CONFIG_COOKIE_IN_OVERLAY** | Security cookie maps to a raw offset ≥ overlay start | Cookie raw offset = 0x6000, overlay starts at 0x5800 | Per‑directory |
| **LOAD_CONFIG_SEH_INVALID** | SEH table is missing, unmapped, out of range, or overlaps overlay; or SEHCount > 0 but SEHTableRVA = 0 | SEHCount = 4, SEHTableRVA = 0 | Per‑directory |

## LOAD CONFIG SUB‑REASONS

Note `unmapped` is emitted by **both** codes below. A consumer must pair the
sub‑reason with its parent code to identify which check fired — the two are
not distinguishable by sub‑reason alone.

### LOAD_CONFIG_COOKIE_INVALID

| Sub‑reason | Meaning |
|------------|---------|
| unmapped | The security-cookie RVA maps to no section |
| non_writable_section | The cookie maps to a section without `MEM_WRITE` |

### LOAD_CONFIG_SEH_INVALID

| Sub‑reason | Meaning |
|------------|---------|
| missing_table_rva | `SEHCount > 0` but `SEHTableRVA` is absent or zero |
| out_of_range | `SEHTableRVA + (SEHCount × 4)` exceeds SizeOfImage |
| unmapped | The SEH table RVA maps to no section |
| in_overlay | The SEH table's raw offset lies at or past the overlay start |

---

## EXPORT ANOMALIES

### Export Directory Anomalies
| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_DIRECTORY_INVALID_HEADER** |	The 40‑byte IMAGE_EXPORT_DIRECTORY header could not be decoded, or its declared counts and array RVAs are mutually inconsistent (e.g., NumberOfFunctions > 0 but AddressOfFunctions == 0, or NumberOfNames > NumberOfFunctions) | NumberOfNames = 50, NumberOfFunctions = 20 | Per‑file |
| **EXPORT_DIRECTORY_OUT_OF_BOUNDS** | The export directory's declared (rva, size) extends past SizeOfImage | Directory RVA = 0x1F0000, size = 0x1000, SizeOfImage = 0x1F0500 | Per‑file |
| **EXPORT_TABLE_TRUNCATED** | One of the export sub‑tables (EAT, ENPT, EOT) declares more entries than the file physically contains, or pe.get_data failed to read the declared extent | NumberOfFunctions = 1000, EAT physical extent only covers 50 entries | Per‑file |

### Export Name Pointer Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_NAME_RVA_INVALID** | A name pointer entry's RVA is zero, missing, or points to a string that could not be read or was unterminated within the maximum scan length | Name RVA = 0x0, or RVA points to bytes with no NUL terminator within 1024 bytes | Per‑entry |
| **EXPORT_NAME_NOT_ASCII**	| A name string decoded successfully but contains non‑printable bytes or characters outside the printable ASCII range (0x20–0x7E) | Name = "Foo\x01Bar", or name decoded with Unicode replacement characters | Per‑entry |
| **EXPORT_NAME_POINTER_TABLE_UNSORTED** | The Export Name Pointer Table is not sorted lexicographically by name, violating the PE spec requirement that enables binary search by GetProcAddress | Names in order: ["Zeta", "Alpha", "Mu"] | Per‑file |
| **EXPORT_NAME_ORDINAL_INDEX_INVALID** | An EOT entry is missing, or its value is greater than or equal to NumberOfFunctions (i.e., it points outside the EAT) | EOT entry = 500, NumberOfFunctions = 100 | Per‑entry |

### Export Function Entry Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_ORDINAL_OUT_OF_RANGE** | The maximum computed ordinal (Base + NumberOfFunctions - 1) exceeds the 16‑bit range. Per PE spec, ordinals must fit in a WORD | Base = 0xFFF0, NumberOfFunctions = 32, max ordinal = 0x1000F | Per‑file |
| **EXPORT_FUNCTION_RVA_INVALID** | A function entry's address RVA is non‑zero, is not a forwarder, and points outside the PE image (>= SizeOfImage) | Address RVA = 0x2000000, SizeOfImage = 0x400000 | Per‑entry |
| **EXPORT_FORWARDER_MALFORMED** | A function entry's RVA points within the export directory (indicating a forwarder) but the resulting string is unreadable, contains non‑printable bytes, or does not match the spec format DllName.SymbolName or DllName.#Ordinal | Forwarder string = "KERNEL32\x01LoadLibraryA", or "InvalidForwarderNoDot" | Per‑entry |

## EXPORT SUB‑REASONS

Several export reason codes carry a `sub_reason` field in their details payload that narrows the pathology. The full taxonomy:

### EXPORT_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The 40‑byte header could not be unpacked from the file bytes |
| eat_rva_zero_with_nonzero_count | NumberOfFunctions > 0 but AddressOfFunctions == 0 |
| enpt_rva_zero_with_nonzero_count | NumberOfNames > 0 but AddressOfNames == 0 |
| eot_rva_zero_with_nonzero_count | NumberOfNames > 0 but AddressOfNameOrdinals == 0 |
| num_names_exceeds_num_functions | NumberOfNames > NumberOfFunctions (impossible in a well‑formed table) |

### EXPORT_TABLE_TRUNCATED

The table field (not sub_reason) identifies the affected sub‑table:

| table value | Meaning |
|-------------|---------|
| export_directory_header | The 40‑byte header itself was short |
| eat_truncated, enpt_truncated, eot_truncated | A sub‑table's declared size exceeded available file bytes |
| eat_read_failed, enpt_read_failed, eot_read_failed | pe.get_data raised when reading the sub‑table |
| eat_rva_zero, enpt_rva_zero, eot_rva_zero | RVA was zero despite a non‑zero declared count |

### EXPORT_NAME_RVA_INVALID

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| name_rva_missing | Parser did not capture the entry's name RVA |
| name_rva_zero | RVA was explicitly zero |
| rva_zero | `_read_asciiz` was called with a zero RVA (defensive; currently unreachable, since the zero case is caught earlier) |
| read_failed | pe.get_data raised when reading the name string |
| empty_read | The read returned zero bytes |
| unterminated | No NUL terminator found within the maximum scan length |

### EXPORT_NAME_NOT_ASCII

Priority‑resolved:

| Sub‑reason | Meaning |
|------------|---------|
| non_ascii	| Decode produced Unicode replacement characters |
| name_not_printable_ascii | Decoded successfully but contains bytes outside 0x20–0x7E |

### EXPORT_NAME_ORDINAL_INDEX_INVALID

| Sub‑reason | Meaning |
|------------|---------|
| missing | Parser could not read the EOT entry |
| out_of_range | Ordinal index >= NumberOfFunctions |
| duplicate | Two or more name pointers resolve to the same EAT index; only the last is reflected in the function view, so an export name is silently unreachable through the resolved-function list |

### EXPORT_ORDINAL_OUT_OF_RANGE

| Sub‑reason | Meaning |
|------------|---------|
| max_exceeds_u16 | Base + NumberOfFunctions − 1 > 0xFFFF |

### EXPORT_FORWARDER_MALFORMED

| Sub‑reason | Meaning |
|------------|---------|
| unreadable | RVA points into export directory but string could not be decoded |
| format | Decoded fine but does not match DllName.SymbolName or DllName.#Ordinal |

### EXPORT_FUNCTION_RVA_INVALID

| Sub‑reason | Meaning |
|------------|---------|
| exceeds_image	 | Address RVA >= SizeOfImage |

---

## DELAY‑LOAD IMPORT ANOMALIES

### Delay‑Load Directory Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **DELAY_IMPORT_DIRECTORY_INVALID_HEADER** | The delay‑load directory's parser could not complete top‑level decoding (e.g., the directory placement could not be read, or initial structures were unrecoverable) | Directory at RVA that pefile cannot resolve to a section | Per‑file |
| **DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS** | The delay‑load directory's declared (rva, size) extends past SizeOfImage | Directory RVA = 0xFF000, size = 0x4000, SizeOfImage = 0x100000 | Per‑file |
| **DELAY_IMPORT_TABLE_TRUNCATED** | One of the delay‑load sub‑tables (descriptor array, INT, IAT, bound IAT, unload IAT) declares more entries than the file physically contains, or pe.get_data failed to read the declared extent, or no zero‑descriptor terminator was found before reaching the directory's declared end | Descriptor count of 50 but only 12 fit in declared size; or INT walk hits max imports without NULL thunk | Per‑file |

### Delay‑Load Descriptor Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **DELAY_IMPORT_DESCRIPTOR_INVALID** | A per‑descriptor structural error: the INT or IAT RVA is zero despite the descriptor being non‑terminating, the sub‑table read failed, or the sub‑table was unparseable. Affects one descriptor at a time | Descriptor for "gdiplus.dll" has int_rva = 0 | Per‑descriptor |
| **DELAY_IMPORT_DLL_NAME_INVALID** | A descriptor's DLL name RVA points to a string that is zero, unreadable, unterminated within the maximum scan length, or contains non‑printable bytes | Name RVA = 0x0, or name = "kernel32\x01dll" | Per‑descriptor |
| **DELAY_IMPORT_INT_IAT_MISMATCH** | A descriptor's Import Name Table and Import Address Table have different lengths. Per spec, they must be parallel arrays of identical length terminated by a NULL thunk | INT has 14 entries, IAT has 12 entries — strong malformation signal | Per‑descriptor |
| **DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE** | A descriptor's Attributes field has the low bit clear, indicating v0 (pre‑Windows 2000) mode where table fields are raw VAs rather than RVAs. Vanishingly rare in modern binaries | Attributes = 0x00000000 instead of 0x00000001 | Per‑descriptor |

### Delay‑Load Entry Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **DELAY_IMPORT_ENTRY_INVALID** | A per‑import entry has structural malformation: the INT thunk is missing or zero, an ordinal value is zero (invalid), or the IMAGE_IMPORT_BY_NAME structure is malformed (unreadable, too short, unterminated, or non‑printable name) | INT entry with high bit set but ordinal = 0; or hint+name structure with NUL‑less buffer | Per‑entry |

## DELAY‑LOAD IMPORT SUB‑REASONS

Most delay‑load reason codes carry a `sub_reason` field in their details payload that narrows the pathology. The full taxonomy:

### DELAY_IMPORT_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not complete top‑level decoding of the delay‑load directory |

### DELAY_IMPORT_TABLE_TRUNCATED

The table field (not sub_reason) identifies the affected sub‑table:

| table value | Meaning |
|-------------|---------|
| delay_import_descriptor_truncated | A descriptor's 32‑byte structure was short |
| delay_import_descriptor_read_failed | pe.get_data raised when reading a descriptor |
| delay_import_descriptor_unterminated | No zero descriptor found before the directory's declared end |
| delay_import_descriptor_max_exceeded | Hit the hard descriptor limit (4096) without finding a NULL terminator |
| int_truncated, iat_truncated | A sub‑table's declared extent exceeded available file bytes |
| int_read_failed, iat_read_failed | pe.get_data raised when reading a thunk |
| int_max_exceeded, iat_max_exceeded | Hit the imports‑per‑descriptor limit (16384) without finding a NULL terminator |
| int_unpack_failed, iat_unpack_failed | struct.unpack failed on a thunk value |

### DELAY_IMPORT_DESCRIPTOR_INVALID

Carries both `table` and `sub_reason` in details:

| table	+ sub-reason (priority order) | Meaning |
|-------------------------------|---------|
| int: int_rva_zero | INT RVA is zero despite the descriptor being non‑terminating |
| int: int_truncated, int_read_failed, int_max_exceeded, int_unpack_failed | Sub‑table read or parse failure (also surfaces via DELAY_IMPORT_TABLE_TRUNCATED) |
| iat: iat_rva_zero | IAT RVA is zero |
| iat: iat_truncated, iat_read_failed, iat_max_exceeded, iat_unpack_failed | Same as INT |

### DELAY_IMPORT_DLL_NAME_INVALID

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| dll_name_rva_zero | DLL name RVA was explicitly zero |
| read_failed | pe.get_data raised when reading the DLL name string |
| empty_read | The read returned zero bytes |
| unterminated | No NUL terminator found within the maximum scan length (512 bytes) |
| non_ascii | Decode produced Unicode replacement characters |
| dll_name_empty | The string terminated immediately — a zero-length DLL name |
| dll_name_not_printable | Contains bytes outside 0x20–0x7E |
| dll_name_too_long | Exceeds 255 characters, the NTFS filename component limit |

### DELAY_IMPORT_INT_IAT_MISMATCH

No sub‑reasons; the code itself names the pathology. Cross‑table length disagreement.

### DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE

No sub‑reasons. Fires when the Attributes field's low bit is zero.

### DELAY_IMPORT_ENTRY_INVALID

Priority‑resolved:

| Sub‑reason | Meaning |
|------------|---------|
| int_entry_missing | Parser could not read this entry's INT thunk |
| int_entry_zero | INT entry is zero at an unexpected position (terminator before INT length matches IAT) |
| ordinal_zero | High bit set on INT entry but ordinal value is zero |
| name_read_failed | pe.get_data raised when reading the IMAGE_IMPORT_BY_NAME structure |
| name_too_short | IMAGE_IMPORT_BY_NAME buffer was less than 3 bytes |
| hint_unpack_failed | Could not unpack the WORD hint |
| name_unterminated | Name string had no NUL terminator within the maximum scan length |
| name_non_ascii | Name decode produced Unicode replacement characters |
| name_empty | The symbol name terminated immediately — a zero-length import name |
| name_not_printable | Name decoded successfully but contains non‑printable bytes |

---

## **IMPORT ANOMALIES**

*Added in v0.7.6.2 (validator §2.16). Backed by the `pe_imports` struct-level
decoder over the 20-byte `IMAGE_IMPORT_DESCRIPTOR` array. Directory placement
and bounds remain owned by the RVA-graph backbone — both the import directory
(index 1) and the IAT directory (index 12) are plain RVAs, so this validator
defers entirely rather than double-counting. The bound-import directory
(index 11) is a separate structure and is not decoded. Absence of an import
directory is not a defect.*

> **`OriginalFirstThunk == 0` is legal here.** Unlike the delay-load INT, a
> zero `OriginalFirstThunk` is common: older linkers emit only `FirstThunk`,
> which then holds INT-style thunks on disk. The parser falls back to it and
> records `thunk_source: "iat_fallback"` **without** raising an anomaly. Only
> when the descriptor is *also* old-style bound — so `FirstThunk` holds
> resolved addresses rather than thunks — are names genuinely unrecoverable.

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **IMPORT_DIRECTORY_INVALID_HEADER** | Top-level decode failure; short-circuits every later import check | Descriptor array unreadable at the declared RVA | Per‑file |
| **IMPORT_TABLE_TRUNCATED** | A parser truncation tag surfaced while walking the descriptor array or a thunk array | Descriptor array reaches the declared end with no zero terminator | Per‑file *(one issue per tag; `table` names the cause)* |
| **IMPORT_DESCRIPTOR_INVALID** | A descriptor identifies a module but has no readable source of imported symbol names | Old-style bound with `OriginalFirstThunk = 0`; or both thunk RVAs zero | Per‑descriptor *(priority-resolved sub-reason)* |
| **IMPORT_DLL_NAME_INVALID** | A descriptor's DLL name RVA is zero, unreadable, unterminated, empty, non-printable, or exceeds the filename limit | Name RVA = 0x0, or name = `"kernel32\x01dll"` | Per‑descriptor *(priority-resolved sub-reason)* |
| **IMPORT_ENTRY_INVALID** | A per-import entry is malformed: a zero ordinal, or an `IMAGE_IMPORT_BY_NAME` that is unreadable, too short, unterminated, empty or non-printable | Thunk with the high bit set but ordinal = 0 | Per‑entry *(priority-resolved; emission capped, see below)* |

## IMPORT SUB‑REASONS

### IMPORT_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not complete top-level decoding; the `errors` key lists the contributing parser tags |

### IMPORT_TABLE_TRUNCATED

The `table` field (not `sub_reason`) identifies the truncation cause. Thunk
tags are prefixed by the array actually read, so a consumer can tell whether
the INT or the fallback IAT was short:

| table value | Meaning |
|-------------|---------|
| import_descriptor_truncated | A descriptor's 20-byte structure came back short |
| import_descriptor_read_failed | `pe.get_data` raised while reading a descriptor |
| import_descriptor_unterminated | The declared directory size was reached with no zero descriptor |
| import_descriptor_max_exceeded | Hit the hard descriptor limit (4096) without finding a terminator |
| int_truncated / iat_fallback_truncated | A thunk read came back shorter than the pointer width |
| int_read_failed / iat_fallback_read_failed | `pe.get_data` raised while reading a thunk |
| int_unpack_failed / iat_fallback_unpack_failed | `struct.unpack` failed on a thunk (defensive; unreachable past the length guard) |
| int_max_exceeded / iat_fallback_max_exceeded | Hit the imports-per-descriptor limit (16384) without a NULL thunk |

### IMPORT_DESCRIPTOR_INVALID

Priority‑resolved; the first matching tag wins. Mutually exclusive in
practice — the parser returns immediately after recording either:

| Sub‑reason | Meaning |
|------------|---------|
| names_unrecoverable_bound_no_int | The descriptor is old-style bound (`TimeDateStamp` neither 0 nor 0xFFFFFFFF) and `OriginalFirstThunk` is zero, so `FirstThunk` holds resolved addresses and no name table exists |
| no_thunk_array | Both `OriginalFirstThunk` and `FirstThunk` are zero — the descriptor names no imports at all |

Details carry `bound_state`, `original_first_thunk` and `first_thunk` so the
reason a name source is unavailable is visible without re-reading the file.

### IMPORT_DLL_NAME_INVALID

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| dll_name_rva_zero | The descriptor's Name RVA was explicitly zero |
| rva_zero | `_read_asciiz` was called with a zero RVA (defensive; the zero case is caught earlier) |
| read_failed | `pe.get_data` raised when reading the name string |
| empty_read | The read returned zero bytes |
| unterminated | No NUL terminator within the maximum scan length (512 bytes) |
| non_ascii | Decode produced Unicode replacement characters |
| dll_name_empty | The string terminated immediately — a zero-length DLL name |
| dll_name_not_printable | Contains bytes outside 0x20–0x7E |
| dll_name_too_long | Exceeds 255 characters, the NTFS filename component limit |

### IMPORT_ENTRY_INVALID

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| ordinal_zero | High bit set on the thunk but the ordinal value is zero |
| name_rva_zero | The thunk's `IMAGE_IMPORT_BY_NAME` RVA was zero |
| name_read_failed | `pe.get_data` raised when reading the hint+name structure |
| name_too_short | The buffer was fewer than 3 bytes (WORD hint plus at least one name byte) |
| hint_unpack_failed | Could not unpack the WORD hint (defensive) |
| name_unterminated | No NUL terminator within the maximum scan length (1024 bytes) |
| name_non_ascii | Decode produced Unicode replacement characters |
| name_empty | The symbol name terminated immediately — a zero-length import name |
| name_not_printable | Contains bytes outside 0x20–0x7E. Length is not constrained: the 1024-byte read is the only bound, so mangled C++ symbols are accepted |

Emission is capped at 32 issues **per descriptor**; `invalid_entry_count`
always carries the true total for that descriptor. The cap is per-descriptor
rather than per-file, so a heavily malformed first module does not silence
later ones. Note the count is of *invalid* entries, not of the descriptor's
whole import list.

---

## **RELOCATION ANOMALIES**

*Added in v0.7.6 (validator §2.13). Backed by the `pe_relocations` struct-level decoder over `IMAGE_BASE_RELOCATION` blocks. Directory placement/bounds remain owned by the RVA-graph backbone; these codes cover block-stream and per-entry structural truth. `IMAGE_REL_BASED_ABSOLUTE` (type 0) padding entries are never flagged, and absence of a relocation directory is not a defect.*

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RELOCATION_DIRECTORY_INVALID_HEADER** | Top-level decode failure: the directory placement could not be resolved or the first block header was unrecoverable | Directory at an RVA `pe.get_data` cannot resolve | Per‑file |
| **RELOCATION_TABLE_TRUNCATED** | A block header, entry region, or the block walk itself could not be fully read within the declared directory | Block claims 0x200 bytes but only 0x40 remain before directory end | Per‑file |
| **RELOCATION_BLOCK_MALFORMED** | A block is structurally invalid: `SizeOfBlock` below the 8-byte header minimum, not aligned to the 2-byte entry stride, or a non-advancing size that would stall the walk | `SizeOfBlock = 0`, or `SizeOfBlock = 7` | Per‑block *(priority-resolved sub-reason)* |
| **RELOCATION_ENTRY_RVA_INVALID** | A non-ABSOLUTE entry's target (`page_rva + offset`) does not map to any section | Entry target = 0x9000 with no covering section | Per‑entry *(count always reported in details even when emission is capped)* |

## RELOCATION SUB‑REASONS

### RELOCATION_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not complete top-level decoding; short-circuits the block and entry checks |

### RELOCATION_BLOCK_MALFORMED

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| size_of_block_too_small | `SizeOfBlock` below the 8-byte header minimum |
| size_of_block_not_word_aligned | `SizeOfBlock` not a multiple of the 2-byte entry stride |
| entry_count_exceeds_max | Declared entry count exceeded the parser's hard limit |

### RELOCATION_TABLE_TRUNCATED

The `region` field (not `table`, and not `sub_reason`) names the truncated
region:

| region value | Meaning |
|---|---|
| relocation_block_header_truncated | The 8-byte block header did not fit the declared directory window, or came back short |
| relocation_block_read_failed | `pe.get_data` raised while reading a block header |
| relocation_entries_exceed_directory | A block's declared entry region extends past the directory's declared end; the readable portion is clamped and the remainder is not decoded |
| relocation_entries_truncated | The entry array was clamped to the directory end, or came back short |
| relocation_entries_read_failed | `pe.get_data` raised while reading the entry array |
| relocation_block_max_exceeded | The walk hit the 65536-block hard limit |

*Note `relocation_entries_exceed_directory` and `relocation_entries_truncated`
are distinct facts and may both fire for the same block: the former means the
declared size was clamped to the directory window; the latter means the
physical read then came back shorter than even that clamped window.*

### Entry-level: HIGHADJ pairing

`IMAGE_REL_BASED_HIGHADJ` (type 4) occupies two WORD slots per the PE spec —
the type+offset word, followed by a raw 16-bit adjustment value. The parser
threads a pairing state across the entry walk (reset per block, never shared
across blocks) rather than decoding every word independently:

| Entries field | Meaning |
|----------------|---------|
| `adjustment` | Present only on a HIGHADJ entry whose pairing succeeded; holds the raw 16-bit value from the following WORD, verbatim, not decoded as type+offset |

If a HIGHADJ entry is the last word in a block's entry region (no adjustment
word follows), the entry is still recorded, `adjustment` is absent, and the
block carries:

| Sub‑reason (block-level `errors`) | Meaning |
|------------------------------------|---------|
| highadj_missing_adjustment | A HIGHADJ entry had no following word to pair with — the block ended, or was truncated, mid-pair |

---

## **DEBUG DIRECTORY ANOMALIES**

*Added in v0.7.6 (validator §2.14). Backed by the `pe_debug` struct-level decoder over the fixed-stride 28-byte `IMAGE_DEBUG_DIRECTORY` array and the CodeView (RSDS / NB10) records it references. Directory placement/bounds remain owned by the RVA-graph backbone. Absence of a debug directory is not a defect, and entries reachable only via a raw file pointer (no `AddressOfRawData`) are not flagged for mapping.*

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **DEBUG_DIRECTORY_INVALID_HEADER** | Top-level decode failure: the directory placement could not be resolved or the first entry was unrecoverable | Directory at an RVA `pe.get_data` cannot resolve | Per‑file |
| **DEBUG_TABLE_TRUNCATED** | The declared directory size is not a whole multiple of the 28-byte entry stride, or the entry array could not be fully read | Directory size = 0x2A (one and a half entries) | Per‑file |
| **DEBUG_DIRECTORY_ENTRY_MALFORMED** | An entry could not be unpacked, its CodeView blob could not be read, or the CodeView record was malformed / of an unrecognised signature | 28-byte entry short read, or CodeView signature neither `RSDS` nor `NB10` | Per‑entry *(priority-resolved sub-reason)* |
| **DEBUG_ENTRY_RVA_INVALID** | An entry's `AddressOfRawData` region does not map to any section | Debug data RVA = 0x9000 with no covering section | Per‑entry |

## DEBUG SUB‑REASONS

### DEBUG_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not complete top-level decoding; short-circuits the truncation and entry checks |

### DEBUG_DIRECTORY_ENTRY_MALFORMED

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| entry_unpack_failed | The 28-byte IMAGE_DEBUG_DIRECTORY entry could not be unpacked |
| codeview_read_failed | `pe.get_data` raised when reading the CodeView blob |
| codeview_too_short | The CodeView record was shorter than its minimum |
| codeview_rsds_truncated | An RSDS record was truncated |
| codeview_nb10_truncated | An NB10 record was truncated |
| codeview_signature_unknown | The CodeView signature was neither `RSDS` nor `NB10` |
| pdb_path_unterminated | The PDB path had no NUL terminator within the scan length |
| pdb_path_non_ascii | The PDB path decoded but contains non-printable bytes |

*On `pdb_path_unterminated`, pdb_path is still populated — with the region truncated at the 512-byte scan cap — rather than left None. Consumers must check errors before trusting the path.*

### DEBUG_TABLE_TRUNCATED

The `region` field (not `table`, and not `sub_reason`) names the truncated
region:

| region value | Meaning |
|--------------|---------|
| debug_directory_size_not_entry_aligned | Declared directory size is not a whole multiple of the 28-byte entry stride; the partial trailing entry is not decoded |
| debug_directory_entry_count_exceeds_max | Declared entry count exceeded the parser's hard limit (256) and was clamped |
| debug_entry_read_failed | `pe.get_data` raised while reading an entry |
| debug_entry_truncated | An entry read returned fewer than 28 bytes |

---

## **EXCEPTION (.pdata) DIRECTORY ANOMALIES**

*Added in v0.7.6.1 (validator §2.15). Backed by the `pe_exception` struct-level decoder — the deep semantic validator for the x64 `RUNTIME_FUNCTION` table (12-byte entries → `UNWIND_INFO` in `.xdata`) and the ARM/ARM64 8-byte `.pdata` record walk. Directory placement/bounds remain owned by the RVA-graph backbone; these codes cover the sorted function table and its unwind references. Absence of an exception directory is not a defect (x86 images carry no `.pdata`; x64/ARM images may legitimately omit it).*

### Exception Directory Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **EXCEPTION_DIRECTORY_INVALID_HEADER** | Top-level parser decode failure; presence of any top-level error short-circuits all further checks | Directory at an RVA `pe.get_data` cannot resolve | Per‑file |
| **EXCEPTION_DIRECTORY_OUT_OF_BOUNDS** | The directory's `rva + size` extends past SizeOfImage | RVA = 0xF0000, size = 0x4000, SizeOfImage = 0xF2000 | Per‑file |
| **EXCEPTION_DIRECTORY_UNALIGNED** | The directory RVA is not DWORD-aligned (`RUNTIME_FUNCTION` entries must be DWORD-aligned) | RVA = 0x2001 | Per‑file |
| **EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE** | The directory Size is not a whole multiple of the per-entry stride (12 for amd64, 8 for arm) | size = 25, entry_size = 12 (remainder 1) | Per‑file |
| **EXCEPTION_TABLE_TRUNCATED** | A parser truncation tag surfaced while walking the counted entry array | Declared count exceeds the readable region; a partial trailing entry | Per‑file *(one issue per tag; `table` field names the cause)* |
| **EXCEPTION_UNSUPPORTED_MACHINE** | The directory is present on a machine whose `.pdata` format is not deep-parsed (x86, IA-64, unknown). Reported once; the function walk is skipped | `IMAGE_FILE_MACHINE_I386` with a non-empty exception directory | Per‑file |

### Exception Function-Table Entry Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **EXCEPTION_ENTRY_INVALID** | A per-entry parser error tag surfaced (unreadable / unpackable entry, or a zeroed mandatory RVA). Skips the cross-entry checks for that entry | `begin_rva = 0`, or the 12-byte entry could not be unpacked | Per‑entry *(priority-resolved sub-reason)* |
| **EXCEPTION_FUNCTION_RANGE_INVALID** | `BeginAddress >= EndAddress` (empty or inverted range). `EndAddress` is the RVA of the first byte past the function, so a well-formed entry has begin < end | begin = 0x1050, end = 0x1050 (empty); or begin > end (inverted) | Per‑entry *(amd64 only; arm records carry no EndAddress)* |
| **EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS** | One or more of begin / end / unwind RVA fall outside the mapped image | begin_rva = 0x99000, SizeOfImage = 0x40000 | Per‑entry *(`fields` lists the offending RVA names)* |
| **EXCEPTION_ENTRIES_NOT_SORTED** | A `BeginAddress` is lower than the previous entry's. The loader binary-searches this table, so an out-of-order entry silently loses its unwind data at runtime | Entry N begins at 0x1010 after entry N−1 began at 0x1050 | Per‑entry |
| **EXCEPTION_FUNCTION_OVERLAP** | A (sorted) entry's `BeginAddress` falls inside the previous entry's `[begin, end)` range | Entry N begins at 0x1040 while entry N−1 spans 0x1000–0x1050 | Per‑entry |

### Exception Unwind-Info Anomalies (AMD64 UNWIND_INFO)

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **EXCEPTION_UNWIND_INFO_UNALIGNED** | A non-zero `UnwindInfoAddress` is not DWORD-aligned (`UNWIND_INFO` must be DWORD-aligned) | unwind_info_rva = 0x3021 | Per‑entry |
| **EXCEPTION_UNWIND_INFO_INVALID** | The UNWIND_INFO decode surfaced a pathology, or its Version is not 1/2/3, or Flags carry bits outside the known mask (EHANDLER \| UHANDLER \| CHAININFO \| LARGE) | version = 5; or flags = 0x10 (reserved bit set) | Per‑entry *(priority-resolved sub-reason)* |
| **EXCEPTION_UNWIND_CHAIN_INVALID** | An entry sets `UNW_FLAG_CHAININFO` but its chained target is missing, unaligned, out of bounds, or self-referential | chained_rva = 0; or chained_rva == this entry's own unwind_info_rva | Per‑entry *(priority-resolved sub-reason)* |

## EXCEPTION DIRECTORY SUB‑REASONS

Several exception reason codes carry a `sub_reason` (or `table` / `fields`) field in their details payload that narrows the pathology. The full taxonomy:

### EXCEPTION_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The parser could not complete top‑level decoding of the exception directory |

### EXCEPTION_TABLE_TRUNCATED

The `table` field (not `sub_reason`) identifies the truncation cause:

| table value | Meaning |
|------------|---------|
| exception_table_ragged_tail | Declared directory size is not a whole multiple of the entry stride; the partial trailing entry is not decoded |
| exception_table_max_exceeded | Declared entry count exceeded the hard limit (2^20) and was clamped |
| exception_entry_read_failed | pe.get_data raised while reading an entry |
| exception_entry_truncated | An entry's fixed-size structure was short |

### EXCEPTION_ENTRY_INVALID

Priority‑resolved; the first matching tag wins:

| Sub‑reason | Meaning |
|------------|---------|
| entry_unpack_failed | struct.unpack failed on the entry bytes |
| begin_rva_zero | BeginAddress was zero |
| end_rva_zero | EndAddress was zero (amd64) |
| unwind_rva_zero | UnwindInfoAddress was zero (amd64) / xdata RVA was zero (arm unpacked) |

### EXCEPTION_UNWIND_INFO_INVALID

Priority‑resolved:

| Sub‑reason | Meaning |
|------------|---------|
| unwind_read_failed | pe.get_data raised when reading the UNWIND_INFO header |
| unwind_truncated | The 4-byte UNWIND_INFO header was short |
| unwind_unpack_failed | struct.unpack failed on the header bytes |
| unwind_version_invalid | Version field was not 1, 2, or 3 |
| unwind_flags_reserved_bits | Flags carried bits outside EHANDLER \| UHANDLER \| CHAININFO \| LARGE |
| unwind_codes_truncated | The trailing chained RUNTIME_FUNCTION could not be read past the unwind-code array |

### EXCEPTION_UNWIND_CHAIN_INVALID

Priority‑resolved:

| Sub‑reason | Meaning |
|------------|---------|
| chain_target_missing | UNW_FLAG_CHAININFO set but the chained RVA is absent or zero |
| chain_target_unaligned | Chained RVA is not DWORD-aligned |
| chain_target_out_of_bounds | Chained RVA falls outside SizeOfImage |
| chain_self_reference | Chained RVA equals the entry's own UnwindInfoAddress |

### EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS

The `fields` list (not `reason`) names each RVA that fell outside the image:

| fields value | Meaning |
|------------|---------|
| begin_rva | BeginAddress < 0 or ≥ SizeOfImage |
| end_rva | EndAddress < 0 or > SizeOfImage |
| unwind_info_rva | UnwindInfoAddress (non-zero) < 0 or ≥ SizeOfImage |

---

## **PACKER HEURISTICS (Interpretation Layer)**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **PACKER_SECTION_NAME** | Section name matches known packer patterns | `.upx0`, `.upx1`, `.aspack` | Per‑section |
| **PACKER_HIGH_ENTROPY_SECTION** | High entropy in code section | `.text` entropy = 7.8 | Per‑section |
| **PACKER_HIGH_ENTROPY_OVERLAY** | Overlay entropy high | Overlay = encrypted blob | Per‑file |
| **PACKER_UNIFORM_HIGH_ENTROPY_PATTERN** | All sections uniformly high entropy | UPX‑like packed binary | Per‑file |
