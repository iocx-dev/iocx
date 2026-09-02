# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

class ReasonCodes:
    # --- Section anomalies ---
    SECTION_RWX = "section_rwx"
    SECTION_NON_EXECUTABLE_CODE_LIKE = "section_non_executable_code_like"
    SECTION_NAME_NON_ASCII = "section_name_non_ascii"
    SECTION_NAME_EMPTY_OR_PADDING = "section_name_empty_or_padding"
    SECTION_IMPOSSIBLE_FLAGS = "section_impossible_flags"
    SECTION_OVERLAP = "section_overlap"
    SECTION_RAW_MISALIGNED = "section_raw_misaligned"

    SECTION_RAW_OVERLAP = "section_raw_overlap"
    SECTION_OVERLAPS_HEADERS = "section_overlaps_headers"
    SECTION_OUT_OF_ORDER_RAW = "section_out_of_order_raw"
    SECTION_OUT_OF_ORDER_VIRTUAL = "section_out_of_order_virtual"
    SECTION_ZERO_LENGTH = "section_zero_length"
    SECTION_DISCARDABLE_CODE = "section_discardable_code"
    SECTION_FLAGS_INCONSISTENT = "section_flags_inconsistent"
    SECTION_CODELIKE_NAME_NOT_EXECUTABLE = "section_codelike_name_not_executable"

    # --- Entrypoint issues ---
    ENTRYPOINT_OUT_OF_BOUNDS = "entrypoint_out_of_bounds"
    ENTRYPOINT_SECTION_NOT_EXECUTABLE = "entrypoint_section_not_executable"
    ENTRYPOINT_IN_TRUNCATED_REGION = "entrypoint_in_truncated_region"
    ENTRYPOINT_IN_OVERLAY = "entrypoint_in_overlay"

    ENTRYPOINT_ZERO_OR_NEGATIVE = "entrypoint_zero_or_negative"
    ENTRYPOINT_IN_HEADERS = "entrypoint_in_headers"
    ENTRYPOINT_IN_NON_CODE_SECTION = "entrypoint_in_non_code_section"
    ENTRYPOINT_IN_DISCARDABLE_SECTION = "entrypoint_in_discardable_section"

    # --- RVA / directory inconsistencies ---
    DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE = "data_directory_zero_rva_nonzero_size"
    DATA_DIRECTORY_ZERO_SIZE_NONZERO_RVA = "data_directory_zero_size_nonzero_rva"
    DATA_DIRECTORY_OUT_OF_RANGE = "data_directory_out_of_range"
    DATA_DIRECTORY_OVERLAP = "data_directory_overlap"
    DATA_DIRECTORY_ZERO_SIZE_UNEXPECTED = "data_directory_zero_size_unexpected"
    DATA_DIRECTORY_INVALID_RANGE = "data_directory_invalid_range"
    DATA_DIRECTORY_IN_HEADERS = "data_directory_in_headers"
    DATA_DIRECTORY_IN_OVERLAY = "data_directory_in_overlay"
    DATA_DIRECTORY_NOT_MAPPED_TO_SECTION = "data_directory_not_mapped_to_section"
    DATA_DIRECTORY_SPANS_MULTIPLE_SECTIONS = "data_directory_spans_multiple_sections"
    DATA_DIRECTORY_RAW_MISMATCH = "data_directory_raw_mismatch"
    IMPORT_RVA_INVALID = "import_rva_invalid"

    # --- Optional header anomalies ---
    OPTIONAL_HEADER_INCONSISTENT_SIZE = "optional_header_inconsistent_size"
    OPTIONAL_HEADER_INVALID_SIZE_OF_HEADERS = "optional_header_invalid_size_of_headers"
    OPTIONAL_HEADER_INVALID_SECTION_ALIGNMENT = "optional_header_invalid_section_alignment"
    OPTIONAL_HEADER_INVALID_FILE_ALIGNMENT = "optional_header_invalid_file_alignment"
    OPTIONAL_HEADER_SIZE_FIELDS_INCONSISTENT = "optional_header_size_fields_inconsistent"
    OPTIONAL_HEADER_IMAGE_BASE_MISALIGNED = "optional_header_image_base_misaligned"
    OPTIONAL_HEADER_INVALID_NUMBER_OF_RVA_AND_SIZES = "optional_header_invalid_number_of_rva_and_sizes"
    OPTIONAL_HEADER_SIZE_OF_IMAGE_MISALIGNED = "optional_header_size_of_image_misaligned"

    # --- TLS anomalies ---
    TLS_MULTIPLE_DIRECTORIES = "tls_multiple_directories"
    TLS_INVALID_RANGE = "tls_invalid_range"
    TLS_ZERO_LENGTH_DIRECTORY = "tls_zero_length_directory"
    TLS_CALLBACKS_MISSING = "tls_callbacks_missing"

    TLS_CALLBACK_OUTSIDE_RANGE = "callback_outside_tls_range"
    TLS_CALLBACK_NOT_MAPPED_TO_SECTION = "tls_callback_not_mapped_to_section"
    TLS_CALLBACK_IN_NON_EXECUTABLE_SECTION = "tls_callback_in_non_executable_section"
    TLS_CALLBACK_IN_HEADERS = "tls_callback_in_headers"
    TLS_CALLBACK_IN_OVERLAY = "tls_callback_in_overlay"

    # (future extension)
    TLS_CALLBACK_ARRAY_NOT_TERMINATED = "tls_callback_array_not_terminated"

    TLS_DIRECTORY_TRUNCATED = "tls_directory_truncated"
    TLS_CALLBACK_RVA_INVALID = "tls_callback_rva_invalid"

    # --- Signature anomalies ---
    SIGNATURE_FLAG_SET_BUT_NO_METADATA = "signature_flag_set_but_no_metadata"
    SIGNATURE_PRESENT_BUT_FLAG_NOT_SET = "signature_present_but_flag_not_set"

    SIGNATURE_MULTIPLE_CERTIFICATES = "signature_multiple_certificates"

    SIGNATURE_INVALID_LENGTH = "signature_invalid_length"
    SIGNATURE_INVALID_REVISION = "signature_invalid_revision"
    SIGNATURE_INVALID_TYPE = "signature_invalid_type"

    SIGNATURE_OUT_OF_FILE_BOUNDS = "signature_out_of_file_bounds"
    SIGNATURE_OVERLAPS_OTHER_DATA = "signature_overlaps_other_data"

    # --- Entropy anomalies ---
    ENTROPY_HIGH_SECTION = "entropy_high_section"
    ENTROPY_HIGH_OVERLAY = "entropy_high_overlay"
    ENTROPY_UNIFORM_ACROSS_SECTIONS = "entropy_uniform_across_sections"

    ENTROPY_VERY_LOW_SECTION = "entropy_very_low_section"

    ENTROPY_HIGH_RESOURCES = "entropy_high_resources"
    ENTROPY_HIGH_RELOCATIONS = "entropy_high_relocations"
    ENTROPY_HIGH_IMPORTS = "entropy_high_imports"
    ENTROPY_HIGH_TLS = "entropy_high_tls"
    ENTROPY_HIGH_CERTIFICATE = "entropy_high_certificate"

    # --- Resource directory anomalies ---
    RESOURCE_DIRECTORY_OUT_OF_BOUNDS = "resource_directory_out_of_bounds"
    RESOURCE_DIRECTORY_LOOP = "resource_directory_loop"
    RESOURCE_ENTRY_OUT_OF_BOUNDS = "resource_entry_out_of_bounds"
    RESOURCE_DIRECTORY_ZERO_LENGTH = "resource_directory_zero_length"
    RESOURCE_DIRECTORY_LANGUAGE_NOT_ID = "resource_directory_language_not_id"

    # --- Resource data anomalies ---
    RESOURCE_DATA_OUT_OF_BOUNDS = "resource_data_out_of_bounds"
    RESOURCE_DATA_OVERLAPS_OTHER_DATA = "resource_data_overlaps_other_data"
    RESOURCE_DATA_AT_INVALID_DEPTH = "resource_data_at_invalid_depth"

    # --- Resource version info ---
    RESOURCE_VERSIONINFO_INVALID_HEADER = "resource_versioninfo_invalid_header"
    RESOURCE_VERSIONINFO_INVALID_FIXEDINFO = "resource_versioninfo_invalid_fixedinfo"
    RESOURCE_VERSIONINFO_INVALID_STRINGFILEINFO = "resource_versioninfo_invalid_stringfileinfo"
    RESOURCE_VERSIONINFO_INVALID_VARFILEINFO = "resource_versioninfo_invalid_varfileinfo"

    # --- Resource string-table anomalies ---
    RESOURCE_STRING_TABLE_CORRUPT = "resource_string_table_corrupt"
    RESOURCE_STRING_TABLE_UNREADABLE = "resource_string_table_unreadable"

    # --- Load Config Directory structural issues ---
    LOAD_CONFIG_TOO_SMALL = "load_config_too_small"
    LOAD_CONFIG_TRUNCATED = "load_config_truncated"

    # Guard CF metadata consistency
    LOAD_CONFIG_GUARD_CF_INCONSISTENT = "load_config_guard_cf_inconsistent"

    # Security cookie issues
    LOAD_CONFIG_COOKIE_INVALID = "load_config_cookie_invalid"
    LOAD_CONFIG_COOKIE_IN_OVERLAY = "load_config_cookie_in_overlay"

    # SEH table issues
    LOAD_CONFIG_SEH_INVALID = "load_config_seh_invalid"

    # --- Export directory anomalies ---
    EXPORT_DIRECTORY_INVALID_HEADER = "export_directory_invalid_header"
    EXPORT_DIRECTORY_OUT_OF_BOUNDS = "export_directory_out_of_bounds"
    EXPORT_TABLE_TRUNCATED = "export_table_truncated"

    # --- Export name pointer anomalies ---
    EXPORT_NAME_RVA_INVALID = "export_name_rva_invalid"
    EXPORT_NAME_NOT_ASCII = "export_name_not_ascii"
    EXPORT_NAME_POINTER_TABLE_UNSORTED = "export_name_pointer_table_unsorted"
    EXPORT_NAME_ORDINAL_INDEX_INVALID = "export_name_ordinal_index_invalid"

    # --- Export function entry anomalies ---
    EXPORT_ORDINAL_OUT_OF_RANGE = "export_ordinal_out_of_range"
    EXPORT_FUNCTION_RVA_INVALID = "export_function_rva_invalid"
    EXPORT_FORWARDER_MALFORMED = "export_forwarder_malformed"

    # --- Delay-load import directory anomalies ---
    DELAY_IMPORT_DIRECTORY_INVALID_HEADER = "delay_import_directory_invalid_header"
    DELAY_IMPORT_DIRECTORY_OUT_OF_BOUNDS = "delay_import_directory_out_of_bounds"
    DELAY_IMPORT_TABLE_TRUNCATED = "delay_import_table_truncated"

    # --- Delay-load descriptor anomalies ---
    DELAY_IMPORT_DESCRIPTOR_INVALID = "delay_import_descriptor_invalid"
    DELAY_IMPORT_DLL_NAME_INVALID = "delay_import_dll_name_invalid"
    DELAY_IMPORT_INT_IAT_MISMATCH = "delay_import_int_iat_mismatch"
    DELAY_IMPORT_ATTRIBUTES_LEGACY_VA_MODE = "delay_import_attributes_legacy_va_mode"

    # --- Delay-load entry anomalies ---
    DELAY_IMPORT_ENTRY_INVALID = "delay_import_entry_invalid"

    # —-- Certificate table (WIN_CERTIFICATE) ---
    CERTIFICATE_TABLE_MALFORMED = "certificate_table_malformed"
    CERTIFICATE_OFFSET_INSIDE_IMAGE = "certificate_offset_inside_image"

    # --— Relocations (IMAGE_BASE_RELOCATION) ---
    RELOCATION_DIRECTORY_INVALID_HEADER = "relocation_directory_invalid_header"
    RELOCATION_TABLE_TRUNCATED = "relocation_table_truncated"
    RELOCATION_BLOCK_MALFORMED = "relocation_block_malformed"
    RELOCATION_ENTRY_RVA_INVALID = "relocation_entry_rva_invalid"

    # --- Debug directory (IMAGE_DEBUG_DIRECTORY) ---
    DEBUG_DIRECTORY_INVALID_HEADER = "debug_directory_invalid_header"
    DEBUG_TABLE_TRUNCATED = "debug_table_truncated"
    DEBUG_DIRECTORY_ENTRY_MALFORMED = "debug_directory_entry_malformed"
    DEBUG_ENTRY_RVA_INVALID = "debug_entry_rva_invalid"

    # --- Exception directory (.pdata / IMAGE_DIRECTORY_ENTRY_EXCEPTION) ---
    # Deep semantic validator for the x64 RUNTIME_FUNCTION table (and ARM/ARM64
    # table walk). Directory placement is owned by rva_graph; these codes cover
    # the sorted function table and its UNWIND_INFO references.
    EXCEPTION_DIRECTORY_INVALID_HEADER = "exception_directory_invalid_header"
    EXCEPTION_DIRECTORY_OUT_OF_BOUNDS = "exception_directory_out_of_bounds"
    EXCEPTION_DIRECTORY_UNALIGNED = "exception_directory_unaligned"
    EXCEPTION_DIRECTORY_SIZE_NOT_MULTIPLE = "exception_directory_size_not_multiple"
    EXCEPTION_TABLE_TRUNCATED = "exception_table_truncated"
    EXCEPTION_UNSUPPORTED_MACHINE = "exception_unsupported_machine"

    # --- Exception function-table entry anomalies ---
    EXCEPTION_ENTRY_INVALID = "exception_entry_invalid"
    EXCEPTION_FUNCTION_RANGE_INVALID = "exception_function_range_invalid"
    EXCEPTION_FUNCTION_RVA_OUT_OF_BOUNDS = "exception_function_rva_out_of_bounds"
    EXCEPTION_ENTRIES_NOT_SORTED = "exception_entries_not_sorted"
    EXCEPTION_FUNCTION_OVERLAP = "exception_function_overlap"

    # --- Exception unwind-info anomalies (AMD64 UNWIND_INFO) ---
    EXCEPTION_UNWIND_INFO_UNALIGNED = "exception_unwind_info_unaligned"
    EXCEPTION_UNWIND_INFO_INVALID = "exception_unwind_info_invalid"
    EXCEPTION_UNWIND_CHAIN_INVALID = "exception_unwind_chain_invalid"

    # ---- Import table ----
    IMPORT_DIRECTORY_INVALID_HEADER = "import_directory_invalid_header"
    IMPORT_TABLE_TRUNCATED = "import_table_truncated"
    IMPORT_DESCRIPTOR_INVALID = "import_descriptor_invalid"
    IMPORT_DLL_NAME_INVALID = "import_dll_name_invalid"
    IMPORT_ENTRY_INVALID = "import_entry_invalid"

    # --- Packer heuristics (interpretation layer) ---
    PACKER_SECTION_NAME = "packer_section_name"
    PACKER_HIGH_ENTROPY_SECTION = "high_entropy_section"
    PACKER_HIGH_ENTROPY_OVERLAY = "high_entropy_overlay"
    PACKER_UNIFORM_HIGH_ENTROPY_PATTERN = "uniform_high_entropy_pattern"
