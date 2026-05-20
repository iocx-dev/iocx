# **Master Structural Adversarial Fixture Reference**
### *Complete cross‑validator adversarial coverage*

Each row contains:

- **Fixture name** (canonical identifier)
- **Edge case exposed**
- **Expected heuristics fired** (exact ReasonCodes)

---

# **1. Entrypoint Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `entrypoint_zero` | EP = 0 | `ENTRYPOINT_ZERO_OR_NEGATIVE` |
| `entrypoint_negative` | EP = 0xFFFFFFFF | `ENTRYPOINT_ZERO_OR_NEGATIVE`, `ENTRYPOINT_OUT_OF_BOUNDS` |
| `entrypoint_in_headers` | EP < SizeOfHeaders | `ENTRYPOINT_IN_HEADERS` |
| `entrypoint_gap_between_sections` | EP between sections | `ENTRYPOINT_OUT_OF_BOUNDS` (`within_size_of_image_but_no_section`) |
| `entrypoint_non_exec_section` | EP in non‑executable section | `ENTRYPOINT_SECTION_NOT_EXECUTABLE`, `ENTRYPOINT_IN_NON_CODE_SECTION` |
| `entrypoint_rsrc` | EP in `.rsrc` | `ENTRYPOINT_IN_NON_CODE_SECTION` |
| `entrypoint_discardable` | EP in discardable section | `ENTRYPOINT_IN_DISCARDABLE_SECTION` |
| `entrypoint_zero_length_section` | EP in section with VS=0 | `ENTRYPOINT_IN_TRUNCATED_REGION` |
| `entrypoint_beyond_virtual_size` | EP >= VA+VS | `ENTRYPOINT_IN_TRUNCATED_REGION` |
| `entrypoint_in_overlay` | EP raw offset ≥ overlay | `ENTRYPOINT_IN_OVERLAY` |

---

# **2. Section Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `sections_rwx` | RWX section | `SECTION_RWX` |
| `sections_code_not_exec` | CNT_CODE but no EXECUTE | `SECTION_NON_EXECUTABLE_CODE_LIKE` |
| `sections_codelike_not_exec` | `.text` but not executable | `SECTION_CODELIKE_NAME_NOT_EXECUTABLE` |
| `sections_non_ascii_name` | Non‑ASCII name | `SECTION_NAME_NON_ASCII` |
| `sections_empty_name` | All nulls/whitespace | `SECTION_NAME_EMPTY_OR_PADDING` |
| `sections_impossible_flags` | DISCARDABLE + EXECUTE + WRITE | `SECTION_IMPOSSIBLE_FLAGS` |
| `sections_raw_misaligned` | RawAddress % FileAlignment != 0 | `SECTION_RAW_MISALIGNED` |
| `sections_overlap_headers` | RawAddress < SizeOfHeaders | `SECTION_OVERLAPS_HEADERS` |
| `sections_zero_length` | VS=0 and RawSize=0 | `SECTION_ZERO_LENGTH` |
| `sections_raw_overlap` | Raw ranges overlap | `SECTION_RAW_OVERLAP` |
| `sections_virtual_overlap` | VA ranges overlap | `SECTION_OVERLAP` |
| `sections_out_of_order_raw` | Raw addresses unsorted | `SECTION_OUT_OF_ORDER_RAW` |
| `sections_out_of_order_virtual` | VA unsorted | `SECTION_OUT_OF_ORDER_VIRTUAL` |
| `sections_negative_fields` | Negative VA/Raw | (no crash; may trigger overlaps/misalignment) |

---

# **3. Optional Header Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `optional_header_size_of_image_too_small` | Max section end > SizeOfImage | `OPTIONAL_HEADER_INCONSISTENT_SIZE` |
| `optional_header_size_of_headers_misaligned` | SizeOfHeaders % FileAlignment != 0 | `OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS` |
| `optional_header_size_of_headers_too_small` | SizeOfHeaders < header_end | `OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS` |
| `optional_header_section_alignment_invalid` | SectionAlignment < FileAlignment OR not power‑of‑two | `OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT` |
| `optional_header_file_alignment_invalid` | FileAlignment not power‑of‑two or outside 512–64K | `OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT` |
| `optional_header_size_fields_too_small` | SizeOfCode/Init/Uninit < computed totals | `OPTIONAL_HEADER_SIZE_FIELDS_INCONSISTENT` |
| `optional_header_image_base_misaligned` | ImageBase % 64K != 0 | `OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED` |
| `optional_header_num_dirs_invalid` | NumberOfRvaAndSizes < 0 or > 16 | `OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES` |
| `optional_header_num_dirs_too_small` | len(dirs) > num_dirs | `OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES` |
| `optional_header_size_of_image_misaligned` | SizeOfImage % SectionAlignment != 0 | `OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED` |

---

# **4. RVA Graph (Data Directory) Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `data_directory_negative_rva` | rva < 0 | `DATA_DIRECTORY_INVALID_RANGE` |
| `data_directory_negative_size` | size < 0 | `DATA_DIRECTORY_INVALID_RANGE` |
| `data_directory_zero_zero` | rva=0,size=0 | (no issue unless required) |
| `data_directory_zero_rva_nonzero_size` | rva=0,size>0 | `DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE` |
| `data_directory_zero_size_nonzero_rva` | size=0,rva>0 | `DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA` |
| `data_directory_in_headers` | rva < SizeOfHeaders | `DATA_DIRECTORY_IN_HEADERS` |
| `data_directory_out_of_range` | rva+size > SizeOfImage | `DATA_DIRECTORY_OUT_OF_RANGE` |
| `data_directory_raw_mismatch` | RVA maps to section VA but raw offset outside raw range | `DATA_DIRECTORY_RAW_MISMATCH` |
| `data_directory_in_overlay` | raw_offset ≥ overlay | `DATA_DIRECTORY_IN_OVERLAY` |
| `data_directory_not_mapped` | No section intersects | `DATA_DIRECTORY_NOT_MAPPED_TO_SECTION` |
| `data_directory_spans_sections` | Intersects >1 section | `DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS` |
| `data_directory_overlap` | Directory ranges overlap | `DATA_DIRECTORY_OVERLAP` |

---

# **5. TLS Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `tls_negative_rva` | start/end/callback < 0 | `TLS_INVALID_RANGE` |
| `tls_directory_in_headers` | start < SizeOfHeaders | (should add) `TLS_DIRECTORY_IN_HEADERS` |
| `tls_directory_in_overlay` | directory raw offset ≥ overlay | (should add) `TLS_DIRECTORY_IN_OVERLAY` |
| `tls_directory_not_mapped` | start/end not in any section | `TLS_INVALID_RANGE` or new `TLS_DIRECTORY_NOT_MAPPED_TO_SECTION` |
| `tls_directory_spans_sections` | [start,end) crosses sections | (should add) `TLS_DIRECTORY_SPANS_MULTIPLE_SECTIONS` |
| `tls_callback_zero_length_section` | callback in VS=0 section | `TLS_CALLBACK_NOT_MAPPED_TO_SECTION` |
| `tls_callback_in_writable_section` | callback in writable section | (should add) `TLS_CALLBACK_IN_WRITABLE_SECTION` |
| `tls_callback_in_discardable_section` | callback in discardable section | (should add) `TLS_CALLBACK_IN_DISCARDABLE_SECTION` |
| `tls_callback_in_rsrc` | callback in `.rsrc` | `TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION` |
| `tls_directory_synthetic_range` | absurdly large end-start | `TLS_INVALID_RANGE` |

---

# **6. Signature Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `signature_negative_offset` | offset < 0 | `SIGNATURE_OUT_OF_FILE_BOUNDS` |
| `signature_negative_size` | size < 0 | `SIGNATURE_OUT_OF_FILE_BOUNDS` |
| `signature_offset_overflow` | offset+size wraps or > file_size | `SIGNATURE_OUT_OF_FILE_BOUNDS` |
| `signature_in_headers` | offset < SizeOfHeaders | `SIGNATURE_OVERLAPS_OTHER_DATA` |
| `signature_overlaps_text` | overlaps `.text` | `SIGNATURE_OVERLAPS_OTHER_DATA` |
| `signature_overlaps_rdata` | overlaps `.rdata` | `SIGNATURE_OVERLAPS_OTHER_DATA` |
| `signature_overlaps_reloc` | overlaps `.reloc` | `SIGNATURE_OVERLAPS_OTHER_DATA` |
| `signature_entirely_in_overlay` | certificate after overlay | (no issue) |
| `signature_invalid_revision` | revision not 0x0100/0x0200 | `SIGNATURE_INVALID_REVISION` |
| `signature_invalid_type` | type not 0x0001/0x0002 | `SIGNATURE_INVALID_TYPE` |
| `signature_missing_fields` | missing revision/type | corresponding invalid heuristics |
| `signature_multiple_mixed_validity` | >1 cert | `SIGNATURE_MULTIPLE_CERTIFICATES` + individual issues |
| `signature_exactly_at_eof` | offset+size == file_size | (valid) |
| `signature_one_byte_past_eof` | offset+size == file_size+1 | `SIGNATURE_OUT_OF_FILE_BOUNDS` |
| `signature_zero_length` | size < 8 | `SIGNATURE_INVALID_LENGTH` |

---

# **7. Resource Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `resources_directory_zero_length` | directory size=0 | `RESOURCE_DIRECTORY_ZERO_LENGTH` |
| `resources_directory_loop` | recursive directory | `RESOURCE_DIRECTORY_LOOP` |
| `resources_directory_partially_outside_rsrc` | directory straddles boundary | `RESOURCE_ENTRY_OUT_OF_BOUNDS` |
| `resources_entry_out_of_bounds` | child directory outside `.rsrc` | `RESOURCE_ENTRY_OUT_OF_BOUNDS` |
| `resources_data_zero_size` | data_size=0 | `RESOURCE_DATA_OUT_OF_BOUNDS` |
| `resources_data_partially_outside_rsrc` | data spans outside `.rsrc` | `RESOURCE_DATA_OUT_OF_BOUNDS` |
| `resources_data_out_of_file_bounds` | raw+size > file_size | `RESOURCE_DATA_OUT_OF_BOUNDS` |
| `resources_data_overlaps_overlay` | raw overlaps overlay | `RESOURCE_DATA_OVERLAPS_OTHER_DATA` |
| `resources_data_overlaps_text` | raw/VA overlaps `.text` | `RESOURCE_DATA_OVERLAPS_OTHER_DATA` |
| `resources_data_overlaps_rdata` | raw/VA overlaps `.rdata` | `RESOURCE_DATA_OVERLAPS_OTHER_DATA` |
| `resources_string_table_outside_rsrc` | string table outside `.rsrc` | `RESOURCE_STRING_TABLE_CORRUPT` |

---

# **8. Entropy Fixtures**

| Fixture | Edge Case | Expected Heuristics |
|--------|-----------|---------------------|
| `entropy_nan_section` | entropy = NaN | (ignored; no crash) |
| `entropy_inf_section` | entropy = inf | may trigger high‑entropy heuristics |
| `entropy_negative_section` | entropy < 0 | ignored |
| `entropy_small_section_high` | raw_size < 1024 | ignored |
| `entropy_small_section_low` | raw_size < 1024 | ignored |
| `entropy_zero_length_section` | raw_size=0 | ignored |
| `entropy_overlay_exact_threshold` | overlay_size=1024, entropy>=7.5 | `ENTROPY_HIGH_OVERLAY` |
| `entropy_overlay_just_below_threshold` | overlay_size=1023 | no issue |
| `entropy_overlay_nan` | overlay entropy NaN | ignored |
| `entropy_overlay_negative` | overlay entropy < 0 | ignored |
| `entropy_region_missing_fields` | missing entropy/size | ignored |
| `entropy_region_nan` | region entropy NaN | ignored |
| `entropy_region_negative` | region entropy < 0 | ignored |
| `entropy_region_small_size` | region size < 1024 | ignored |
| `entropy_uniform_nan` | NaN in entropies | no uniform heuristic |
| `entropy_uniform_inf` | inf in entropies | may trigger uniform |
| `entropy_uniform_negative` | negative values | ignored |
