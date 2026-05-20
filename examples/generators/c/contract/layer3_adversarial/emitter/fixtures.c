#include "fixtures.h"
#include <string.h>

/* -----------------------------------------
 * Baseline sections
 * ----------------------------------------- */

static SectionSpec BASE_SECTIONS[3] = {
    { ".text", 0x1000, 0x1000, 0x400, 0x200, 0x60000020 },
    { ".rdata", 0x2000, 0x1000, 0x600, 0x200, 0x40000040 },
    { ".rsrc", 0x3000, 0x1000, 0x800, 0x200, 0x40000040 },
};

/* -----------------------------------------
 * Baseline initializer
 * ----------------------------------------- */

static void apply_baseline(FixtureSpec *f)
{
    memset(f, 0, sizeof(*f));

    f->image_base = 0x400000;
    f->size_of_headers = 0x400;
    f->file_alignment = 0x200;
    f->section_alignment = 0x1000;
    f->size_of_image = 0x4000;

    f->sections = BASE_SECTIONS;
    f->section_count = 3;

    f->directory_count = 0;
    f->overlay_pattern = 0x00;
}

/* -----------------------------------------
 * Global fixtures array
 * ----------------------------------------- */

FixtureSpec FIXTURES[FIXTURE_COUNT];

/* -----------------------------------------
 * One builder per fixture
 * ----------------------------------------- */
/* Entrypoint fixtures */

static void build_entrypoint_zero(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_zero";

    /* EP = 0 */
    f->entrypoint_rva = 0;
}

static void build_entrypoint_negative(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_negative";

    /* Negative via wraparound */
    f->entrypoint_rva = 0xFFFFFFFF;
}

static void build_entrypoint_in_headers(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_in_headers";

    /* Inside headers (< size_of_headers = 0x400) */
    f->entrypoint_rva = 0x200;
}

static void build_entrypoint_gap_between_sections(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_gap_between_sections";

    /*
     * Gap between:
     * .text VA=0x1000 VS=0x1000 → covers 0x1000–0x1FFF
     * .rdata VA=0x2000
     * So 0x1F00 is inside the gap.
     */
    f->entrypoint_rva = 0x1F00;
}

static void build_entrypoint_non_exec_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_non_exec_section";

    /* EP inside .rdata (non-executable) */
    f->entrypoint_rva = BASE_SECTIONS[1].va + 0x10;
}

static void build_entrypoint_rsrc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_rsrc";

    /* EP inside .rsrc */
    f->entrypoint_rva = BASE_SECTIONS[2].va + 0x20;
}

static void build_entrypoint_discardable(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_discardable";

    /* Mark .text as discardable */
    BASE_SECTIONS[0].characteristics |= 0x02000000; /* IMAGE_SCN_MEM_DISCARDABLE */

    /* EP inside .text */
    f->entrypoint_rva = BASE_SECTIONS[0].va + 0x10;
}

static void build_entrypoint_zero_length_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_zero_length_section";

    /* Make .text zero-length */
    BASE_SECTIONS[0].vs = 0;

    /* EP inside zero-length section */
    f->entrypoint_rva = BASE_SECTIONS[0].va;
}

static void build_entrypoint_beyond_virtual_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_beyond_virtual_size";

    /* Shrink .text VS so EP is beyond it */
    BASE_SECTIONS[0].vs = 0x100;

    /* EP far beyond VS */
    f->entrypoint_rva = BASE_SECTIONS[0].va + 0x800;
}

static void build_entrypoint_in_overlay(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entrypoint_in_overlay";

    /*
     * Overlay begins at raw offset >= size_of_image.
     * So EP RVA >= size_of_image is "in overlay".
     */
    f->entrypoint_rva = f->size_of_image + 0x1000;
}

/* Section fixtures */

static void build_sections_rwx(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_rwx";

    /* Make .text RWX: add WRITE bit */
    BASE_SECTIONS[0].characteristics |= 0x80000000; /* IMAGE_SCN_MEM_WRITE */
}

static void build_sections_code_not_exec(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_code_not_exec";

    /*
     * CNT_CODE but no EXECUTE:
     * - ensure CNT_CODE bit set
     * - clear EXECUTE bit
     */
    BASE_SECTIONS[0].characteristics |= 0x00000020; /* IMAGE_SCN_CNT_CODE */
    BASE_SECTIONS[0].characteristics &= ~0x20000000; /* clear IMAGE_SCN_MEM_EXECUTE */
}

static void build_sections_codelike_not_exec(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_codelike_not_exec";

    /*
     * ".text" but not executable:
     * keep name ".text", clear EXECUTE bit
     */
    BASE_SECTIONS[0].characteristics &= ~0x20000000; /* clear IMAGE_SCN_MEM_EXECUTE */
}

static void build_sections_non_ascii_name(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_non_ascii_name";

    /* Non-ASCII section name */
    static const char non_ascii_name[] = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8";
    BASE_SECTIONS[0].name = non_ascii_name;
}

static void build_sections_empty_name(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_empty_name";

    /* Empty / padding-like name */
    BASE_SECTIONS[0].name = "";
}

static void build_sections_impossible_flags(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_impossible_flags";

    /*
     * DISCARDABLE + EXECUTE + WRITE (and read, for realism)
     * IMAGE_SCN_MEM_DISCARDABLE 0x02000000
     * IMAGE_SCN_MEM_EXECUTE 0x20000000
     * IMAGE_SCN_MEM_READ 0x40000000
     * IMAGE_SCN_MEM_WRITE 0x80000000
     */
    BASE_SECTIONS[0].characteristics |=
        0x02000000 | 0x20000000 | 0x40000000 | 0x80000000;
}

static void build_sections_raw_misaligned(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_raw_misaligned";

    /*
     * RawAddress % FileAlignment != 0
     * FileAlignment = 0x200, so 0x410 is misaligned.
     */
    BASE_SECTIONS[0].raw = 0x410;
}

static void build_sections_overlap_headers(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_overlap_headers";

    /*
     * RawAddress < SizeOfHeaders (0x400)
     * So section raw starts inside headers.
     */
    BASE_SECTIONS[0].raw = 0x200;
}

static void build_sections_zero_length(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_zero_length";

    /* VS=0 and RawSize=0 */
    BASE_SECTIONS[0].vs = 0;
    BASE_SECTIONS[0].raw_size = 0;
}

static void build_sections_raw_overlap(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_raw_overlap";

    /*
     * Baseline:
     * .text raw=0x400 size=0x200 → 0x400–0x5FF
     * .rdata raw=0x600 size=0x200 → 0x600–0x7FF
     *
     * Make .rdata overlap .text by moving it into .text range.
     */
    BASE_SECTIONS[1].raw = 0x500; /* overlaps 0x400–0x5FF */
    BASE_SECTIONS[1].raw_size = 0x200;
}

static void build_sections_virtual_overlap(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_virtual_overlap";

    /*
     * Baseline:
     * .text VA=0x1000 VS=0x1000 → 0x1000–0x1FFF
     * .rdata VA=0x2000
     *
     * Move .rdata VA into .text range.
     */
    BASE_SECTIONS[1].va = 0x1800; /* overlaps .text */
}

static void build_sections_out_of_order_raw(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_out_of_order_raw";

    /*
     * Make raw addresses unsorted:
     * .text raw=0x600
     * .rdata raw=0x400
     */
    BASE_SECTIONS[0].raw = 0x600;
    BASE_SECTIONS[1].raw = 0x400;
}

static void build_sections_out_of_order_virtual(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_out_of_order_virtual";

    /*
     * Make VA unsorted:
     * .text VA=0x2000
     * .rdata VA=0x1000
     */
    BASE_SECTIONS[0].va = 0x2000;
    BASE_SECTIONS[1].va = 0x1000;
}

static void build_sections_negative_fields(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sections_negative_fields";

    /*
     * "Negative" via unsigned wrap:
     * VA and Raw set to 0xFFFFFFFF.
     * This may trigger overlaps/misalignment heuristics,
     * but should not crash your code.
     */
    BASE_SECTIONS[0].va = 0xFFFFFFFF;
    BASE_SECTIONS[0].raw = 0xFFFFFFFF;
}

/* Optional header fixtures */

static void build_opt_size_of_image_too_small(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_size_of_image_too_small";

    /*
     * Max section end = 0x4000 (baseline)
     * Make SizeOfImage smaller than that.
     */
    f->size_of_image = 0x2000; /* too small */
}

static void build_opt_size_of_headers_misaligned(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_size_of_headers_misaligned";

    /*
     * SizeOfHeaders % FileAlignment != 0
     * FileAlignment = 0x200 → misaligned = 0x300
     */
    f->size_of_headers = 0x300;
}

static void build_opt_size_of_headers_too_small(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_size_of_headers_too_small";

    /*
     * SizeOfHeaders < header_end
     * header_end ≈ 0x400 baseline → make it smaller
     */
    f->size_of_headers = 0x100;
}

static void build_opt_section_alignment_invalid(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_section_alignment_invalid";

    /*
     * SectionAlignment < FileAlignment OR not power-of-two.
     * FileAlignment = 0x200 → choose 0x180 (not power-of-two).
     */
    f->section_alignment = 0x180;
}

static void build_opt_file_alignment_invalid(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_file_alignment_invalid";

    /*
     * FileAlignment must be power-of-two between 512 and 64K.
     * Choose 0x300 (not power-of-two).
     */
    f->file_alignment = 0x300;
}

static void build_opt_size_fields_too_small(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_size_fields_too_small";

    /*
     * These fields are not explicitly in FixtureSpec,
     * but your validator likely computes them from sections.
     *
     * To simulate "too small", shrink SizeOfImage so that
     * computed totals exceed it.
     */
    f->size_of_image = 0x1000; /* smaller than .text alone */
}

static void build_opt_image_base_misaligned(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_image_base_misaligned";

    /*
     * ImageBase must be 64K aligned.
     * 0x400000 is aligned; choose 0x401234 (not aligned).
     */
    f->image_base = 0x401234;
}

static void build_opt_num_dirs_invalid(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_num_dirs_invalid";

    /*
     * NumberOfRvaAndSizes < 0 or > 16.
     * Use >16 (e.g., 20).
     */
    f->directory_count = 20;
}

static void build_opt_num_dirs_too_small(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_num_dirs_too_small";

    /*
     * len(dirs) > num_dirs
     * Provide 2 directories but claim only 1.
     */
    f->directories[0].rva = 0x1000;
    f->directories[0].size = 0x20;

    f->directories[1].rva = 0x2000;
    f->directories[1].size = 0x20;

    f->directory_count = 1; /* too small */
}

static void build_opt_size_of_image_misaligned(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "opt_size_of_image_misaligned";

    /*
     * SizeOfImage % SectionAlignment != 0
     * SectionAlignment = 0x1000 → choose 0x1800.
     */
    f->size_of_image = 0x1800;
}

/* Data directory fixtures */

static void build_ddir_negative_rva(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_negative_rva";

    /* Negative via wraparound */
    f->directories[0].rva = 0xFFFFFFFF;
    f->directories[0].size = 0x20;
    f->directory_count = 1;
}

static void build_ddir_negative_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_negative_size";

    /* Negative via wraparound */
    f->directories[0].rva = 0x2000;
    f->directories[0].size = 0xFFFFFFFF;
    f->directory_count = 1;
}

static void build_ddir_zero_zero(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_zero_zero";

    /* rva=0, size=0 is allowed */
    f->directories[0].rva = 0;
    f->directories[0].size = 0;
    f->directory_count = 1;
}

static void build_ddir_zero_rva_nonzero_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_zero_rva_nonzero_size";

    f->directories[0].rva = 0;
    f->directories[0].size = 0x40;
    f->directory_count = 1;
}

static void build_ddir_zero_size_nonzero_rva(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_zero_size_nonzero_rva";

    f->directories[0].rva = 0x2000;
    f->directories[0].size = 0;
    f->directory_count = 1;
}

static void build_ddir_in_headers(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_in_headers";

    /* rva < SizeOfHeaders (0x400) */
    f->directories[0].rva = 0x200;
    f->directories[0].size = 0x40;
    f->directory_count = 1;
}

static void build_ddir_out_of_range(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_out_of_range";

    /* rva + size > SizeOfImage (0x4000) */
    f->directories[0].rva = 0x3F00;
    f->directories[0].size = 0x200; /* extends past 0x4000 */
    f->directory_count = 1;
}

static void build_ddir_raw_mismatch(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_raw_mismatch";

    /*
     * RVA maps to .text VA range (0x1000–0x1FFF)
     * but raw offset is outside .text raw range (0x400–0x5FF).
     *
     * Choose RVA=0x1100 (inside .text)
     * but size large enough to map raw beyond raw_size.
     */
    f->directories[0].rva = 0x1100;
    f->directories[0].size = 0x800; /* too large → raw mismatch */
    f->directory_count = 1;
}

static void build_ddir_in_overlay(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_in_overlay";

    /*
     * Overlay begins at RVA >= size_of_image (0x4000)
     */
    f->directories[0].rva = f->size_of_image + 0x100;
    f->directories[0].size = 0x40;
    f->directory_count = 1;
}

static void build_ddir_not_mapped(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_not_mapped";

    /*
     * No section covers RVA=0x5000
     */
    f->directories[0].rva = 0x5000;
    f->directories[0].size = 0x40;
    f->directory_count = 1;
}

static void build_ddir_spans_sections(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_spans_sections";

    /*
     * Span .text (0x1000–0x1FFF) and .rdata (0x2000–0x2FFF)
     * Use RVA=0x1F00 size=0x200 → crosses boundary
     */
    f->directories[0].rva = 0x1F00;
    f->directories[0].size = 0x200;
    f->directory_count = 1;
}

static void build_ddir_overlap(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "ddir_overlap";

    /*
     * Two directories whose RVA ranges overlap.
     */
    f->directories[0].rva = 0x2000;
    f->directories[0].size = 0x200;

    f->directories[1].rva = 0x2100; /* overlaps 0x2000–0x21FF */
    f->directories[1].size = 0x200;

    f->directory_count = 2;
}

/* TLS fixtures */

static void build_tls_negative_rva(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_negative_rva";

    /* Negative via wraparound */
    f->tls_start = 0xFFFFFFFF;
    f->tls_end = 0xFFFFFFFF;
    f->tls_callbacks = 0xFFFFFFFF;
}

static void build_tls_directory_in_headers(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_directory_in_headers";

    /*
     * TLS directory start < SizeOfHeaders (0x400)
     */
    f->tls_start = 0x200;
    f->tls_end = 0x240;
}

static void build_tls_directory_in_overlay(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_directory_in_overlay";

    /*
     * Overlay begins at RVA >= size_of_image (0x4000)
     */
    f->tls_start = f->size_of_image + 0x100;
    f->tls_end = f->tls_start + 0x40;
}

static void build_tls_directory_not_mapped(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_directory_not_mapped";

    /*
     * No section covers RVA=0x5000
     */
    f->tls_start = 0x5000;
    f->tls_end = 0x5040;
}

static void build_tls_directory_spans_sections(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_directory_spans_sections";

    /*
     * Span .text (0x1000–0x1FFF) and .rdata (0x2000–0x2FFF)
     */
    f->tls_start = 0x1F00;
    f->tls_end = 0x2100; /* crosses into .rdata */
}

static void build_tls_callback_zero_length_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_callback_zero_length_section";

    /*
     * Make .text zero-length
     */
    BASE_SECTIONS[0].vs = 0;

    /*
     * Callback inside zero-length .text
     */
    f->tls_callbacks = BASE_SECTIONS[0].va;
}

static void build_tls_callback_in_writable_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_callback_in_writable_section";

    /*
     * Mark .rdata writable
     */
    BASE_SECTIONS[1].characteristics |= 0x80000000; /* IMAGE_SCN_MEM_WRITE */

    /*
     * Callback inside .rdata
     */
    f->tls_callbacks = BASE_SECTIONS[1].va + 0x10;
}

static void build_tls_callback_in_discardable_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_callback_in_discardable_section";

    /*
     * Mark .rdata discardable
     */
    BASE_SECTIONS[1].characteristics |= 0x02000000; /* IMAGE_SCN_MEM_DISCARDABLE */

    /*
     * Callback inside .rdata
     */
    f->tls_callbacks = BASE_SECTIONS[1].va + 0x20;
}

static void build_tls_callback_in_rsrc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_callback_in_rsrc";

    /*
     * Callback inside .rsrc
     */
    f->tls_callbacks = BASE_SECTIONS[2].va + 0x30;
}

static void build_tls_directory_synthetic_range(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "tls_directory_synthetic_range";

    /*
     * Absurdly large range → invalid
     */
    f->tls_start = 0x1000;
    f->tls_end = 0x90000000; /* huge */
}

/* Signature fixtures */

static void build_sig_negative_offset(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_negative_offset";
}

static void build_sig_negative_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_negative_size";
}

static void build_sig_offset_overflow(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_offset_overflow";
}

static void build_sig_in_headers(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_in_headers";
}

static void build_sig_overlaps_text(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_overlaps_text";
}

static void build_sig_overlaps_rdata(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_overlaps_rdata";
}

static void build_sig_overlaps_reloc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_overlaps_reloc";
}

static void build_sig_entirely_in_overlay(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_entirely_in_overlay";
}

static void build_sig_invalid_revision(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_invalid_revision";
}

static void build_sig_invalid_type(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_invalid_type";
}

static void build_sig_missing_fields(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_missing_fields";
}

static void build_sig_multiple_mixed_validity(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_multiple_mixed_validity";
}

static void build_sig_exactly_at_eof(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_exactly_at_eof";
}

static void build_sig_one_byte_past_eof(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_one_byte_past_eof";
}

static void build_sig_zero_length(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "sig_zero_length";
}

/* Resource fixtures */

static void build_res_dir_zero_length(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_dir_zero_length";
}

static void build_res_dir_loop(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_dir_loop";
}

static void build_res_dir_partially_outside_rsrc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_dir_partially_outside_rsrc";
}

static void build_res_entry_out_of_bounds(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_entry_out_of_bounds";
}

static void build_res_data_zero_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_zero_size";
}

static void build_res_data_partially_outside_rsrc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_partially_outside_rsrc";
}

static void build_res_data_out_of_file_bounds(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_out_of_file_bounds";
}

static void build_res_data_overlaps_overlay(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_overlaps_overlay";
}

static void build_res_data_overlaps_text(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_overlaps_text";
}

static void build_res_data_overlaps_rdata(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_data_overlaps_rdata";
}

static void build_res_string_table_outside_rsrc(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "res_string_table_outside_rsrc";
}

/* Entropy fixtures */

static void build_entropy_nan_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_nan_section";
}

static void build_entropy_inf_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_inf_section";
}

static void build_entropy_negative_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_negative_section";
}

static void build_entropy_small_section_high(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_small_section_high";
}

static void build_entropy_small_section_low(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_small_section_low";
}

static void build_entropy_zero_length_section(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_zero_length_section";
}

static void build_entropy_overlay_exact_threshold(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_overlay_exact_threshold";
}

static void build_entropy_overlay_just_below_threshold(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_overlay_just_below_threshold";
}

static void build_entropy_overlay_nan(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_overlay_nan";
}

static void build_entropy_overlay_negative(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_overlay_negative";
}

static void build_entropy_region_missing_fields(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_region_missing_fields";
}

static void build_entropy_region_nan(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_region_nan";
}

static void build_entropy_region_negative(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_region_negative";
}

static void build_entropy_region_small_size(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_region_small_size";
}

static void build_entropy_uniform_nan(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_uniform_nan";
}

static void build_entropy_uniform_inf(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_uniform_inf";
}

static void build_entropy_uniform_negative(FixtureSpec *f)
{
    apply_baseline(f);
    f->name = "entropy_uniform_negative";
}

/* -----------------------------------------
 * Build all fixtures
 * ----------------------------------------- */

void build_all_fixtures(void)
{
    /* Entrypoint fixtures */
    build_entrypoint_zero(&FIXTURES[FIX_ENTRYPOINT_ZERO]);
    build_entrypoint_negative(&FIXTURES[FIX_ENTRYPOINT_NEGATIVE]);
    build_entrypoint_in_headers(&FIXTURES[FIX_ENTRYPOINT_IN_HEADERS]);
    build_entrypoint_gap_between_sections(&FIXTURES[FIX_ENTRYPOINT_GAP_BETWEEN_SECTIONS]);
    build_entrypoint_non_exec_section(&FIXTURES[FIX_ENTRYPOINT_NON_EXEC_SECTION]);
    build_entrypoint_rsrc(&FIXTURES[FIX_ENTRYPOINT_RSRC]);
    build_entrypoint_discardable(&FIXTURES[FIX_ENTRYPOINT_DISCARDABLE]);
    build_entrypoint_zero_length_section(&FIXTURES[FIX_ENTRYPOINT_ZERO_LENGTH_SECTION]);
    build_entrypoint_beyond_virtual_size(&FIXTURES[FIX_ENTRYPOINT_BEYOND_VIRTUAL_SIZE]);
    build_entrypoint_in_overlay(&FIXTURES[FIX_ENTRYPOINT_IN_OVERLAY]);

    /* Section fixtures */
    build_sections_rwx(&FIXTURES[FIX_SECTIONS_RWX]);
    build_sections_code_not_exec(&FIXTURES[FIX_SECTIONS_CODE_NOT_EXEC]);
    build_sections_codelike_not_exec(&FIXTURES[FIX_SECTIONS_CODELIKE_NOT_EXEC]);
    build_sections_non_ascii_name(&FIXTURES[FIX_SECTIONS_NON_ASCII_NAME]);
    build_sections_empty_name(&FIXTURES[FIX_SECTIONS_EMPTY_NAME]);
    build_sections_impossible_flags(&FIXTURES[FIX_SECTIONS_IMPOSSIBLE_FLAGS]);
    build_sections_raw_misaligned(&FIXTURES[FIX_SECTIONS_RAW_MISALIGNED]);
    build_sections_overlap_headers(&FIXTURES[FIX_SECTIONS_OVERLAP_HEADERS]);
    build_sections_zero_length(&FIXTURES[FIX_SECTIONS_ZERO_LENGTH]);
    build_sections_raw_overlap(&FIXTURES[FIX_SECTIONS_RAW_OVERLAP]);
    build_sections_virtual_overlap(&FIXTURES[FIX_SECTIONS_VIRTUAL_OVERLAP]);
    build_sections_out_of_order_raw(&FIXTURES[FIX_SECTIONS_OUT_OF_ORDER_RAW]);
    build_sections_out_of_order_virtual(&FIXTURES[FIX_SECTIONS_OUT_OF_ORDER_VIRTUAL]);
    build_sections_negative_fields(&FIXTURES[FIX_SECTIONS_NEGATIVE_FIELDS]);

    /* Optional header fixtures */
    build_opt_size_of_image_too_small(&FIXTURES[FIX_OPT_SIZE_OF_IMAGE_TOO_SMALL]);
    build_opt_size_of_headers_misaligned(&FIXTURES[FIX_OPT_SIZE_OF_HEADERS_MISALIGNED]);
    build_opt_size_of_headers_too_small(&FIXTURES[FIX_OPT_SIZE_OF_HEADERS_TOO_SMALL]);
    build_opt_section_alignment_invalid(&FIXTURES[FIX_OPT_SECTION_ALIGNMENT_INVALID]);
    build_opt_file_alignment_invalid(&FIXTURES[FIX_OPT_FILE_ALIGNMENT_INVALID]);
    build_opt_size_fields_too_small(&FIXTURES[FIX_OPT_SIZE_FIELDS_TOO_SMALL]);
    build_opt_image_base_misaligned(&FIXTURES[FIX_OPT_IMAGE_BASE_MISALIGNED]);
    build_opt_num_dirs_invalid(&FIXTURES[FIX_OPT_NUM_DIRS_INVALID]);
    build_opt_num_dirs_too_small(&FIXTURES[FIX_OPT_NUM_DIRS_TOO_SMALL]);
    build_opt_size_of_image_misaligned(&FIXTURES[FIX_OPT_SIZE_OF_IMAGE_MISALIGNED]);

    /* Data directory fixtures */
    build_ddir_negative_rva(&FIXTURES[FIX_DDIR_NEGATIVE_RVA]);
    build_ddir_negative_size(&FIXTURES[FIX_DDIR_NEGATIVE_SIZE]);
    build_ddir_zero_zero(&FIXTURES[FIX_DDIR_ZERO_ZERO]);
    build_ddir_zero_rva_nonzero_size(&FIXTURES[FIX_DDIR_ZERO_RVA_NONZERO_SIZE]);
    build_ddir_zero_size_nonzero_rva(&FIXTURES[FIX_DDIR_ZERO_SIZE_NONZERO_RVA]);
    build_ddir_in_headers(&FIXTURES[FIX_DDIR_IN_HEADERS]);
    build_ddir_out_of_range(&FIXTURES[FIX_DDIR_OUT_OF_RANGE]);
    build_ddir_raw_mismatch(&FIXTURES[FIX_DDIR_RAW_MISMATCH]);
    build_ddir_in_overlay(&FIXTURES[FIX_DDIR_IN_OVERLAY]);
    build_ddir_not_mapped(&FIXTURES[FIX_DDIR_NOT_MAPPED]);
    build_ddir_spans_sections(&FIXTURES[FIX_DDIR_SPANS_SECTIONS]);
    build_ddir_overlap(&FIXTURES[FIX_DDIR_OVERLAP]);

    /* TLS fixtures */
    build_tls_negative_rva(&FIXTURES[FIX_TLS_NEGATIVE_RVA]);
    build_tls_directory_in_headers(&FIXTURES[FIX_TLS_DIRECTORY_IN_HEADERS]);
    build_tls_directory_in_overlay(&FIXTURES[FIX_TLS_DIRECTORY_IN_OVERLAY]);
    build_tls_directory_not_mapped(&FIXTURES[FIX_TLS_DIRECTORY_NOT_MAPPED]);
    build_tls_directory_spans_sections(&FIXTURES[FIX_TLS_DIRECTORY_SPANS_SECTIONS]);
    build_tls_callback_zero_length_section(&FIXTURES[FIX_TLS_CALLBACK_ZERO_LENGTH_SECTION]);
    build_tls_callback_in_writable_section(&FIXTURES[FIX_TLS_CALLBACK_IN_WRITABLE_SECTION]);
    build_tls_callback_in_discardable_section(&FIXTURES[FIX_TLS_CALLBACK_IN_DISCARDABLE_SECTION]);
    build_tls_callback_in_rsrc(&FIXTURES[FIX_TLS_CALLBACK_IN_RSRC]);
    build_tls_directory_synthetic_range(&FIXTURES[FIX_TLS_DIRECTORY_SYNTHETIC_RANGE]);

    /* Signature fixtures */
    build_sig_negative_offset(&FIXTURES[FIX_SIG_NEGATIVE_OFFSET]);
    build_sig_negative_size(&FIXTURES[FIX_SIG_NEGATIVE_SIZE]);
    build_sig_offset_overflow(&FIXTURES[FIX_SIG_OFFSET_OVERFLOW]);
    build_sig_in_headers(&FIXTURES[FIX_SIG_IN_HEADERS]);
    build_sig_overlaps_text(&FIXTURES[FIX_SIG_OVERLAPS_TEXT]);
    build_sig_overlaps_rdata(&FIXTURES[FIX_SIG_OVERLAPS_RDATA]);
    build_sig_overlaps_reloc(&FIXTURES[FIX_SIG_OVERLAPS_RELOC]);
    build_sig_entirely_in_overlay(&FIXTURES[FIX_SIG_ENTIRELY_IN_OVERLAY]);
    build_sig_invalid_revision(&FIXTURES[FIX_SIG_INVALID_REVISION]);
    build_sig_invalid_type(&FIXTURES[FIX_SIG_INVALID_TYPE]);
    build_sig_missing_fields(&FIXTURES[FIX_SIG_MISSING_FIELDS]);
    build_sig_multiple_mixed_validity(&FIXTURES[FIX_SIG_MULTIPLE_MIXED_VALIDITY]);
    build_sig_exactly_at_eof(&FIXTURES[FIX_SIG_EXACTLY_AT_EOF]);
    build_sig_one_byte_past_eof(&FIXTURES[FIX_SIG_ONE_BYTE_PAST_EOF]);
    build_sig_zero_length(&FIXTURES[FIX_SIG_ZERO_LENGTH]);

    /* Resource fixtures */
    build_res_dir_zero_length(&FIXTURES[FIX_RES_DIR_ZERO_LENGTH]);
    build_res_dir_loop(&FIXTURES[FIX_RES_DIR_LOOP]);
    build_res_dir_partially_outside_rsrc(&FIXTURES[FIX_RES_DIR_PARTIALLY_OUTSIDE_RSRC]);
    build_res_entry_out_of_bounds(&FIXTURES[FIX_RES_ENTRY_OUT_OF_BOUNDS]);
    build_res_data_zero_size(&FIXTURES[FIX_RES_DATA_ZERO_SIZE]);
    build_res_data_partially_outside_rsrc(&FIXTURES[FIX_RES_DATA_PARTIALLY_OUTSIDE_RSRC]);
    build_res_data_out_of_file_bounds(&FIXTURES[FIX_RES_DATA_OUT_OF_FILE_BOUNDS]);
    build_res_data_overlaps_overlay(&FIXTURES[FIX_RES_DATA_OVERLAPS_OVERLAY]);
    build_res_data_overlaps_text(&FIXTURES[FIX_RES_DATA_OVERLAPS_TEXT]);
    build_res_data_overlaps_rdata(&FIXTURES[FIX_RES_DATA_OVERLAPS_RDATA]);
    build_res_string_table_outside_rsrc(&FIXTURES[FIX_RES_STRING_TABLE_OUTSIDE_RSRC]);

    /* Entropy fixtures */
    build_entropy_nan_section(&FIXTURES[FIX_ENTROPY_NAN_SECTION]);
    build_entropy_inf_section(&FIXTURES[FIX_ENTROPY_INF_SECTION]);
    build_entropy_negative_section(&FIXTURES[FIX_ENTROPY_NEGATIVE_SECTION]);
    build_entropy_small_section_high(&FIXTURES[FIX_ENTROPY_SMALL_SECTION_HIGH]);
    build_entropy_small_section_low(&FIXTURES[FIX_ENTROPY_SMALL_SECTION_LOW]);
    build_entropy_zero_length_section(&FIXTURES[FIX_ENTROPY_ZERO_LENGTH_SECTION]);
    build_entropy_overlay_exact_threshold(&FIXTURES[FIX_ENTROPY_OVERLAY_EXACT_THRESHOLD]);
    build_entropy_overlay_just_below_threshold(&FIXTURES[FIX_ENTROPY_OVERLAY_JUST_BELOW_THRESHOLD]);
    build_entropy_overlay_nan(&FIXTURES[FIX_ENTROPY_OVERLAY_NAN]);
    build_entropy_overlay_negative(&FIXTURES[FIX_ENTROPY_OVERLAY_NEGATIVE]);
    build_entropy_region_missing_fields(&FIXTURES[FIX_ENTROPY_REGION_MISSING_FIELDS]);
    build_entropy_region_nan(&FIXTURES[FIX_ENTROPY_REGION_NAN]);
    build_entropy_region_negative(&FIXTURES[FIX_ENTROPY_REGION_NEGATIVE]);
    build_entropy_region_small_size(&FIXTURES[FIX_ENTROPY_REGION_SMALL_SIZE]);
    build_entropy_uniform_nan(&FIXTURES[FIX_ENTROPY_UNIFORM_NAN]);
    build_entropy_uniform_inf(&FIXTURES[FIX_ENTROPY_UNIFORM_INF]);
    build_entropy_uniform_negative(&FIXTURES[FIX_ENTROPY_UNIFORM_NEGATIVE]);
}
