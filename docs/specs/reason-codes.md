# **PE Structural Reason Codes**

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
| **DATA_DIRECTORY_NOT_MAPPED_TO_SECTION** | Directory is in range but does not fall inside any section | RVA = 0x9000, Size = 0x200, no section covers it | Per‑directory *(suppressed for empty, zero‑RVA, out‑of‑range, zero‑length‑section)* |
| **DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS** | Directory range overlaps more than one section | RVA = 0x1800, Size = 0x1000 spans .text → .rdata | Per‑directory |
| **DATA_DIRECTORY_OVERLAP** | Two directories’ RVA ranges overlap | Import and IAT overlap | Global |
| **IMPORT_RVA_INVALID** | Import RVA does not map to a valid import table structure (import validator) | Import RVA = 0x9000 | Per‑directory |

---

## **TLS ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **TLS_CALLBACK_OUTSIDE_RANGE** | Callback RVA not within the TLS directory’s `start, end)` range | Callback = `0x5000`, TLS range = `0x4000–0x4100` | Per‑file |
| **[TLS_MULTIPLE_DIRECTORIES** | More than one TLS directory is present in the PE | Two `tls_directory` entries in `extended` | Per‑file |
| **TLS_INVALID_RANGE** | TLS directory has `start >= end` (structurally impossible) | Start = `0x6000`, End = `0x6000` | Per‑file |
| **TLS_ZERO_LENGTH_DIRECTORY** | TLS directory exists but `start == end` (zero‑length region) | Start = `0x7000`, End = `0x7000` | Per‑file |
| **TLS_CALLBACKS_MISSING** | TLS directory is non‑empty but callback pointer is `0` | Start = `0x4000`, End = `0x4100`, Callbacks = `0` | Per‑file |
| **TLS_CALLBACK_NOT_MAPPED_TO_SECTION** | Callback RVA does not fall inside any section’s VA range | Callback = `0x90000000` (no section covers it) | Per‑file |
| **TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION** | Callback RVA maps to a section lacking `IMAGE_SCN_MEM_EXECUTE` | Callback in `.data` or `.rdata` | Per‑file |
| **TLS_CALLBACK_IN_HEADERS** | Callback RVA falls inside the PE headers (`< SizeOfHeaders`) | Callback = `0x200`, SizeOfHeaders = `0x600` | Per‑file |
| **TLS_CALLBACK_IN_OVERLAY** | Callback RVA maps to a raw offset beyond the last section (overlay) | Raw offset = `0x1F000`, overlay starts at `0x1E000` | Per‑file |
| **TLS_CALLBACK_ARRAY_NOT_TERMINATED** *(optional future rule)* | Callback array exists but is not 0‑terminated | Callback list ends with non‑zero RVA | Per‑file |

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

## ** RESOURCE ANOMALIES**

### **Resource Directory Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_DIRECTORY_OUT_OF_BOUNDS** | A resource directory RVA/size lies outside the `.rsrc` section or outside `SizeOfImage` | Directory RVA = `0x90000000`, `.rsrc` ends at `0x400000` | Per‑file |
| **RESOURCE_DIRECTORY_LOOP** | Recursive directory traversal detects a cycle (malformed or malicious resource tree) | Directory A → B → A | Per‑file |
| **RESOURCE_DIRECTORY_ZERO_LENGTH** | A resource directory exists but has zero length or no valid entries | RVA = `0x3000`, size = `0` | Per‑file |

### Resource Hierarchy Anomalies
| Reason Code |	What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **RESOURCE_DIRECTORY_LANGUAGE_NOT_ID** | A depth‑2 directory (Language layer) contains a named entry instead of an integer LCID, violating the Type → Name → Language hierarchy | Language entry keyed by "EN-US" instead of LCID 0x0409 | Per‑file
| **RESOURCE_DATA_AT_INVALID_DEPTH** | A data leaf appears at depth 0 (Type) or depth 1 (Name) instead of depth 2 (Language), skipping required hierarchy layers | Root Type directory contains a direct data leaf with no Name/Language subdirectories | Per‑file

### **Resource Entry / Data Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_ENTRY_OUT_OF_BOUNDS** | A resource entry points to a data entry outside the `.rsrc` section or outside `SizeOfImage` | Entry RVA = `0x80000000` | Per‑file |
| **RESOURCE_DATA_OUT_OF_BOUNDS** | Resource data block lies outside the file or outside the `.rsrc` section | Data offset = `0x1F0000`, file size = `0x1E0000` | Per‑file |
| **RESOURCE_DATA_OVERLAPS_OTHER_DATA** | Two resource data blobs overlap in raw or virtual space | Data A: `0x2000–0x2400`, Data B: `0x2300–0x2500` | Per‑file |

### Resource Version‑Info Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **RESOURCE_VERSIONINFO_INVALID_HEADER** | The VS_VERSIONINFO envelope is malformed: placement outside `.rsrc`, `szKey` not equal to "VS_VERSION_INFO", or `wLength` inconsistent with the buffer size | szKey = "VS_VERSION_BAD" instead of "VS_VERSION_INFO" | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_FIXEDINFO** | The embedded VS_FIXEDFILEINFO has an incorrect `dwSignature` (expected `0xFEEF04BD`) or `dwStrucVersion` (expected `0x00010000`), or fails to parse | dwSignature = `0xDEADBEEF` instead of `0xFEEF04BD` | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO** | A StringFileInfo, StringTable, or String child is malformed: invalid length field, non‑hex lang_codepage key, or truncated string entry	StringTable | key = "ENGLISHX" instead of 8‑hex‑char <langID><codepage> form | Per‑file
| **RESOURCE_VERSIONINFO_INVALID_VARFILEINFO** | A VarFileInfo or Var child is malformed, or the Translation array's length is not a DWORD multiple	Var. | wValueLength = 6 (not divisible by 4) for a Translation array | Per‑file

*Note: absence of an RT_VERSION resource is not treated as a structural anomaly — many legitimate binary types (kernel drivers, MSI helpers, cross‑compiled artefacts) omit version‑info entirely.*

### **Resource String‑Table Anomalies**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **RESOURCE_STRING_TABLE_CORRUPT** | String table length, offsets, or UTF‑16 entries are malformed or out of bounds | String count = 32 but table only contains 10 entries | Per‑file |

---

## **ENTROPY ANOMALIES**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **ENTROPY_HIGH_SECTION** | Section entropy ≥ 7.5 and size ≥ 1 KB | `.text` entropy = 7.9 | Per‑section |
| **ENTROPY_HIGH_OVERLAY** | Overlay entropy ≥ 7.5 and size ≥ 1 KB | Overlay entropy = 7.8 | Per‑file |
| **ENTROPY_UNIFORM_ACROSS_SECTIONS** | All sections have high entropy with very low variance | Mean = 7.7, stddev = 0.05 | Per‑file |
| **ENTROPY_VERY_LOW_SECTION** | Large section with entropy ≤ 0.2 (zero‑filled / padding abuse) | `.data` entropy = 0.03 | Per‑section |
| **ENTROPY_HIGH_RESOURCES** | Resource directory entropy ≥ 7.5 | `.rsrc` entropy = 7.9 | Per‑region |
| **ENTROPY_HIGH_RELOCATIONS** | Relocation table entropy ≥ 7.5 | `.reloc` entropy = 7.8 | Per‑region |
| **ENTROPY_HIGH_IMPORTS** | Import table entropy ≥ 7.5 | Import blob entropy = 7.7 | Per‑region |
| **ENTROPY_HIGH_TLS** | TLS directory entropy ≥ 7.5 | TLS entropy = 7.9 | Per‑region |
| **ENTROPY_HIGH_CERTIFICATE** | Certificate blob entropy ≥ 7.5 | WIN_CERTIFICATE entropy = 7.8 | Per‑region |

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

---

## EXPORT ANOMALIES

### Export Directory Anomalies
| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_DIRECTORY_INVALID_HEADER** |	The 40‑byte IMAGE_EXPORT_DIRECTORY header could not be decoded, or its declared counts and array RVAs are mutually inconsistent (e.g., NumberOfFunctions > 0 but AddressOfFunctions == 0, or NumberOfNames > NumberOfFunctions) | NumberOfNames = 50, NumberOfFunctions = 20 | Per‑file
| **EXPORT_DIRECTORY_OUT_OF_BOUNDS** | The export directory's declared (rva, size) extends past SizeOfImage | Directory RVA = 0x1F0000, size = 0x1000, SizeOfImage = 0x1F0500 | Per‑file
| **EXPORT_TABLE_TRUNCATED** | One of the export sub‑tables (EAT, ENPT, EOT) declares more entries than the file physically contains, or pe.get_data failed to read the declared extent | NumberOfFunctions = 1000, EAT physical extent only covers 50 entries | Per‑file

### Export Name Pointer Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_NAME_RVA_INVALID** | A name pointer entry's RVA is zero, missing, or points to a string that could not be read or was unterminated within the maximum scan length | Name RVA = 0x0, or RVA points to bytes with no NUL terminator within 1024 bytes | Per‑entry
| **EXPORT_NAME_NOT_ASCII**	| A name string decoded successfully but contains non‑printable bytes or characters outside the printable ASCII range (0x20–0x7E) | Name = "Foo\x01Bar", or name decoded with Unicode replacement characters | Per‑entry
| **EXPORT_NAME_POINTER_TABLE_UNSORTED** | The Export Name Pointer Table is not sorted lexicographically by name, violating the PE spec requirement that enables binary search by GetProcAddress | Names in order: ["Zeta", "Alpha", "Mu"] | Per‑file
| **EXPORT_NAME_ORDINAL_INDEX_INVALID** | An EOT entry is missing, or its value is greater than or equal to NumberOfFunctions (i.e., it points outside the EAT) | EOT entry = 500, NumberOfFunctions = 100 | Per‑entry

### Export Function Entry Anomalies

| Reason Code | What Triggers It | Example Pattern | Scope |
|-------------|------------------|-----------------|-------|
| **EXPORT_ORDINAL_OUT_OF_RANGE** | The maximum computed ordinal (Base + NumberOfFunctions - 1) exceeds the 16‑bit range. Per PE spec, ordinals must fit in a WORD | Base = 0xFFF0, NumberOfFunctions = 32, max ordinal = 0x1000F | Per‑file
| **EXPORT_FUNCTION_RVA_INVALID** | A function entry's address RVA is non‑zero, is not a forwarder, and points outside the PE image (>= SizeOfImage) | Address RVA = 0x2000000, SizeOfImage = 0x400000 | Per‑entry
| **EXPORT_FORWARDER_MALFORMED** | A function entry's RVA points within the export directory (indicating a forwarder) but the resulting string is unreadable, contains non‑printable bytes, or does not match the spec format DllName.SymbolName or DllName.#Ordinal | Forwarder string = "KERNEL32\x01LoadLibraryA", or "InvalidForwarderNoDot" | Per‑entry

## EXPORT SUB‑REASONS

Several export reason codes carry a reason field in their details payload that narrows the pathology. The full taxonomy:

### EXPORT_DIRECTORY_INVALID_HEADER

| Sub‑reason | Meaning |
|------------|---------|
| top_level_decode | The 40‑byte header could not be unpacked from the file bytes |
| eat_rva_zero_with_nonzero_count | NumberOfFunctions > 0 but AddressOfFunctions == 0 |
| enpt_rva_zero_with_nonzero_count | NumberOfNames > 0 but AddressOfNames == 0 |
| eot_rva_zero_with_nonzero_count | NumberOfNames > 0 but AddressOfNameOrdinals == 0 |
| num_names_exceeds_num_functions | NumberOfNames > NumberOfFunctions (impossible in a well‑formed table) |

### EXPORT_TABLE_TRUNCATED

The table field (not reason) identifies the affected sub‑table:

| table value | Meaning
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
| read_failed | pe.get_data raised when reading the name string |
| unterminated | No NUL terminator found within the maximum scan length |

### EXPORT_NAME_NOT_ASCII

Priority‑resolved:

| Sub‑reason | Meaning |
| non_ascii	| Decode produced Unicode replacement characters |
| name_not_printable_ascii | Decoded successfully but contains bytes outside 0x20–0x7E |

### EXPORT_NAME_ORDINAL_INDEX_INVALID

| Sub‑reason | Meaning |
| missing | Parser could not read the EOT entry |
| out_of_range | Ordinal index >= NumberOfFunctions |

### EXPORT_ORDINAL_OUT_OF_RANGE

| Sub‑reason | Meaning |
| max_exceeds_u16 | Base + NumberOfFunctions − 1 > 0xFFFF |

### EXPORT_FORWARDER_MALFORMED

| Sub‑reason | Meaning |
| unreadable | RVA points into export directory but string could not be decoded |
| format | Decoded fine but does not match DllName.SymbolName or DllName.#Ordinal |

### EXPORT_FUNCTION_RVA_INVALID

| Sub‑reason | Meaning |
| exceeds_image	 | Address RVA >= SizeOfImage |

---

## **PACKER HEURISTICS (Interpretation Layer)**

| Reason Code | What Triggers It | Example Pattern | Scope |
|------------|------------------|-----------------|--------|
| **PACKER_SECTION_NAME** | Section name matches known packer patterns | `.upx0`, `.upx1`, `.aspack` | Per‑section |
| **PACKER_HIGH_ENTROPY_SECTION** | High entropy in code section | `.text` entropy = 7.8 | Per‑section |
| **PACKER_HIGH_ENTROPY_OVERLAY** | Overlay entropy high | Overlay = encrypted blob | Per‑file |
| **PACKER_UNIFORM_HIGH_ENTROPY_PATTERN** | All sections uniformly high entropy | UPX‑like packed binary | Per‑file |
