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
    DATA_DIRECTORY_OUT_OF_RANGE = "data_directory_out_of_range"
    DATA_DIRECTORY_OVERLAP = "data_directory_overlap"
    DATA_DIRECTORY_ZERO_RVA_NONZERO_SIZE = "data_directory_zero_rva_nonzero_size"
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
    TLS_CALLBACK_OUTSIDE_RANGE = "callback_outside_tls_range"

    # --- Signature anomalies ---
    SIGNATURE_FLAG_SET_BUT_NO_METADATA = "signature_flag_set_but_no_metadata"

    # --- Entropy anomalies ---
    ENTROPY_HIGH_SECTION = "entropy_high_section"
    ENTROPY_HIGH_OVERLAY = "entropy_high_overlay"
    ENTROPY_UNIFORM_ACROSS_SECTIONS = "entropy_uniform_across_sections"

    # --- Packer heuristics (interpretation layer) ---
    PACKER_SECTION_NAME = "packer_section_name"
    PACKER_HIGH_ENTROPY_SECTION = "high_entropy_section"
    PACKER_HIGH_ENTROPY_OVERLAY = "high_entropy_overlay"
    PACKER_UNIFORM_HIGH_ENTROPY_PATTERN = "uniform_high_entropy_pattern"
