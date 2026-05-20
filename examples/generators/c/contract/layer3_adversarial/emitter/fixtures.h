#ifndef FIXTURES_H
#define FIXTURES_H

#include <stdint.h>
#include <stddef.h>

/* -----------------------------
 * Basic specs
 * ----------------------------- */

typedef struct SectionSpec {
    const char *name;
    uint32_t va;
    uint32_t vs;
    uint32_t raw;
    uint32_t raw_size;
    uint32_t characteristics;
} SectionSpec;

typedef struct DirectorySpec {
    uint32_t rva;
    uint32_t size;
} DirectorySpec;

/* -----------------------------
 * FixtureSpec
 * ----------------------------- */

typedef struct FixtureSpec {
    const char *name;

    /* Optional Header overrides */
    uint32_t entrypoint_rva;
    uint32_t image_base;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t file_alignment;
    uint32_t section_alignment;

    /* Sections (baseline + mutations) */
    SectionSpec *sections;
    size_t section_count;

    /* Data directories (up to 16) */
    DirectorySpec directories[16];
    int directory_count;

    /* TLS fields (optional) */
    int32_t tls_start;
    int32_t tls_end;
    int32_t tls_callbacks;

    /* Overlay (optional) */
    uint32_t overlay_size;
    uint8_t overlay_pattern;

} FixtureSpec;

/* -----------------------------
 * Fixture IDs
 * ----------------------------- */

typedef enum {

    /* Entrypoint fixtures */
    FIX_ENTRYPOINT_ZERO,
    FIX_ENTRYPOINT_NEGATIVE,
    FIX_ENTRYPOINT_IN_HEADERS,
    FIX_ENTRYPOINT_GAP_BETWEEN_SECTIONS,
    FIX_ENTRYPOINT_NON_EXEC_SECTION,
    FIX_ENTRYPOINT_RSRC,
    FIX_ENTRYPOINT_DISCARDABLE,
    FIX_ENTRYPOINT_ZERO_LENGTH_SECTION,
    FIX_ENTRYPOINT_BEYOND_VIRTUAL_SIZE,
    FIX_ENTRYPOINT_IN_OVERLAY,

    /* Section fixtures */
    FIX_SECTIONS_RWX,
    FIX_SECTIONS_CODE_NOT_EXEC,
    FIX_SECTIONS_CODELIKE_NOT_EXEC,
    FIX_SECTIONS_NON_ASCII_NAME,
    FIX_SECTIONS_EMPTY_NAME,
    FIX_SECTIONS_IMPOSSIBLE_FLAGS,
    FIX_SECTIONS_RAW_MISALIGNED,
    FIX_SECTIONS_OVERLAP_HEADERS,
    FIX_SECTIONS_ZERO_LENGTH,
    FIX_SECTIONS_RAW_OVERLAP,
    FIX_SECTIONS_VIRTUAL_OVERLAP,
    FIX_SECTIONS_OUT_OF_ORDER_RAW,
    FIX_SECTIONS_OUT_OF_ORDER_VIRTUAL,
    FIX_SECTIONS_NEGATIVE_FIELDS,

    /* Optional header fixtures */
    FIX_OPT_SIZE_OF_IMAGE_TOO_SMALL,
    FIX_OPT_SIZE_OF_HEADERS_MISALIGNED,
    FIX_OPT_SIZE_OF_HEADERS_TOO_SMALL,
    FIX_OPT_SECTION_ALIGNMENT_INVALID,
    FIX_OPT_FILE_ALIGNMENT_INVALID,
    FIX_OPT_SIZE_FIELDS_TOO_SMALL,
    FIX_OPT_IMAGE_BASE_MISALIGNED,
    FIX_OPT_NUM_DIRS_INVALID,
    FIX_OPT_NUM_DIRS_TOO_SMALL,
    FIX_OPT_SIZE_OF_IMAGE_MISALIGNED,

    /* RVA graph / data directory fixtures */
    FIX_DDIR_NEGATIVE_RVA,
    FIX_DDIR_NEGATIVE_SIZE,
    FIX_DDIR_ZERO_ZERO,
    FIX_DDIR_ZERO_RVA_NONZERO_SIZE,
    FIX_DDIR_ZERO_SIZE_NONZERO_RVA,
    FIX_DDIR_IN_HEADERS,
    FIX_DDIR_OUT_OF_RANGE,
    FIX_DDIR_RAW_MISMATCH,
    FIX_DDIR_IN_OVERLAY,
    FIX_DDIR_NOT_MAPPED,
    FIX_DDIR_SPANS_SECTIONS,
    FIX_DDIR_OVERLAP,

    /* TLS fixtures */
    FIX_TLS_NEGATIVE_RVA,
    FIX_TLS_DIRECTORY_IN_HEADERS,
    FIX_TLS_DIRECTORY_IN_OVERLAY,
    FIX_TLS_DIRECTORY_NOT_MAPPED,
    FIX_TLS_DIRECTORY_SPANS_SECTIONS,
    FIX_TLS_CALLBACK_ZERO_LENGTH_SECTION,
    FIX_TLS_CALLBACK_IN_WRITABLE_SECTION,
    FIX_TLS_CALLBACK_IN_DISCARDABLE_SECTION,
    FIX_TLS_CALLBACK_IN_RSRC,
    FIX_TLS_DIRECTORY_SYNTHETIC_RANGE,

    /* Signature fixtures */
    FIX_SIG_NEGATIVE_OFFSET,
    FIX_SIG_NEGATIVE_SIZE,
    FIX_SIG_OFFSET_OVERFLOW,
    FIX_SIG_IN_HEADERS,
    FIX_SIG_OVERLAPS_TEXT,
    FIX_SIG_OVERLAPS_RDATA,
    FIX_SIG_OVERLAPS_RELOC,
    FIX_SIG_ENTIRELY_IN_OVERLAY,
    FIX_SIG_INVALID_REVISION,
    FIX_SIG_INVALID_TYPE,
    FIX_SIG_MISSING_FIELDS,
    FIX_SIG_MULTIPLE_MIXED_VALIDITY,
    FIX_SIG_EXACTLY_AT_EOF,
    FIX_SIG_ONE_BYTE_PAST_EOF,
    FIX_SIG_ZERO_LENGTH,

    /* Resource fixtures */
    FIX_RES_DIR_ZERO_LENGTH,
    FIX_RES_DIR_LOOP,
    FIX_RES_DIR_PARTIALLY_OUTSIDE_RSRC,
    FIX_RES_ENTRY_OUT_OF_BOUNDS,
    FIX_RES_DATA_ZERO_SIZE,
    FIX_RES_DATA_PARTIALLY_OUTSIDE_RSRC,
    FIX_RES_DATA_OUT_OF_FILE_BOUNDS,
    FIX_RES_DATA_OVERLAPS_OVERLAY,
    FIX_RES_DATA_OVERLAPS_TEXT,
    FIX_RES_DATA_OVERLAPS_RDATA,
    FIX_RES_STRING_TABLE_OUTSIDE_RSRC,

    /* Entropy fixtures */
    FIX_ENTROPY_NAN_SECTION,
    FIX_ENTROPY_INF_SECTION,
    FIX_ENTROPY_NEGATIVE_SECTION,
    FIX_ENTROPY_SMALL_SECTION_HIGH,
    FIX_ENTROPY_SMALL_SECTION_LOW,
    FIX_ENTROPY_ZERO_LENGTH_SECTION,
    FIX_ENTROPY_OVERLAY_EXACT_THRESHOLD,
    FIX_ENTROPY_OVERLAY_JUST_BELOW_THRESHOLD,
    FIX_ENTROPY_OVERLAY_NAN,
    FIX_ENTROPY_OVERLAY_NEGATIVE,
    FIX_ENTROPY_REGION_MISSING_FIELDS,
    FIX_ENTROPY_REGION_NAN,
    FIX_ENTROPY_REGION_NEGATIVE,
    FIX_ENTROPY_REGION_SMALL_SIZE,
    FIX_ENTROPY_UNIFORM_NAN,
    FIX_ENTROPY_UNIFORM_INF,
    FIX_ENTROPY_UNIFORM_NEGATIVE,

    FIXTURE_COUNT

} FixtureId;

/* -----------------------------
 * Globals
 * ----------------------------- */

extern FixtureSpec FIXTURES[FIXTURE_COUNT];

/* Build all fixtures */
void build_all_fixtures(void);

#endif /* FIXTURES_H */
