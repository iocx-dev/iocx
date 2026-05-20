#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

// ---------------------------------------------------------------------
// External PE parser interface (you already have this in your emitter)
// ---------------------------------------------------------------------

typedef struct ParsedPe {
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections;
    int num_sections;
    // plus whatever else your loader uses
} ParsedPe;

int load_pe(const char *path, ParsedPe *pe);
void free_pe(ParsedPe *pe);

// ---------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------

static IMAGE_SECTION_HEADER *find_section_by_name(ParsedPe *pe, const char *name)
{
    for (int i = 0; i < pe->num_sections; ++i) {
        char n[9] = {0};
        memcpy(n, pe->sections[i].Name, 8);
        if (strcmp(n, name) == 0)
            return &pe->sections[i];
    }
    return NULL;
}

static IMAGE_SECTION_HEADER *sec_by_name(ParsedPe *pe, const char *name)
{
    return find_section_by_name(pe, name);
}

static int range_overlap(uint32_t a_start, uint32_t a_size,
                         uint32_t b_start, uint32_t b_size)
{
    uint32_t a_end = a_start + a_size;
    uint32_t b_end = b_start + b_size;
    return (a_start < b_end && b_start < a_end);
}

static IMAGE_DATA_DIRECTORY *dd(ParsedPe *pe, int idx)
{
    if (idx < 0) return NULL;
    if ((uint32_t)idx >= pe->nt->OptionalHeader.NumberOfRvaAndSizes)
        return NULL;
    return &pe->nt->OptionalHeader.DataDirectory[idx];
}

// If you already have rva_to_raw, keep that and remove this stub.
int rva_to_raw(ParsedPe *pe, uint32_t rva, uint32_t *raw_out);

// ---------------------------------------------------------------------
// 1. Entrypoint fixtures
// ---------------------------------------------------------------------

static IMAGE_SECTION_HEADER *section_for_rva(ParsedPe *pe, uint32_t rva)
{
    for (int i = 0; i < pe->num_sections; ++i) {
        uint32_t va = pe->sections[i].VirtualAddress;
        uint32_t vs = pe->sections[i].Misc.VirtualSize;
        if (rva >= va && rva < va + vs)
            return &pe->sections[i];
    }
    return NULL;
}

static int check_entrypoint_zero(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    return ep == 0;
}

static int check_entrypoint_negative(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    return ep == 0xFFFFFFFFu;
}

static int check_entrypoint_in_headers(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;

    return ep == 0x200 && ep < soh;
}

static int check_entrypoint_gap_between_sections(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    return ep == 0x1F00;
}

static int check_entrypoint_non_exec_section(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    IMAGE_SECTION_HEADER *s = section_for_rva(pe, ep);
    if (!s) return 0;

    char name[9] = {0};
    memcpy(name, s->Name, 8);

    return strcmp(name, ".rdata") == 0 &&
           (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;
}

static int check_entrypoint_rsrc(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    IMAGE_SECTION_HEADER *s = section_for_rva(pe, ep);
    if (!s) return 0;

    char name[9] = {0};
    memcpy(name, s->Name, 8);

    return strcmp(name, ".rsrc") == 0;
}

static int check_entrypoint_discardable(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    IMAGE_SECTION_HEADER *s = section_for_rva(pe, ep);
    if (!s) return 0;

    char name[9] = {0};
    memcpy(name, s->Name, 8);

    return strcmp(name, ".text") == 0 &&
           (s->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
}

static int check_entrypoint_zero_length_section(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    IMAGE_SECTION_HEADER *s = section_for_rva(pe, ep);
    if (!s) return 0;

    char name[9] = {0};
    memcpy(name, s->Name, 8);

    return strcmp(name, ".text") == 0 &&
           s->Misc.VirtualSize == 0;
}

static int check_entrypoint_beyond_virtual_size(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return ep == text->VirtualAddress + 0x800 &&
           text->Misc.VirtualSize == 0x100 &&
           ep >= text->VirtualAddress + text->Misc.VirtualSize;
}

static int check_entrypoint_in_overlay(ParsedPe *pe)
{
    uint32_t ep = pe->nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return ep == soi + 0x1000 &&
           ep >= soi;
}

// ---------------------------------------------------------------------
// 2. Section fixtures
// ---------------------------------------------------------------------

static int check_sections_rwx(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    return (text->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
           (text->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
}

static int check_sections_code_not_exec(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    return (text->Characteristics & IMAGE_SCN_CNT_CODE) != 0 &&
           (text->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;
}

static int check_sections_codelike_not_exec(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    return (text->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;
}

static int check_sections_non_ascii_name(ParsedPe *pe)
{
    if (pe->num_sections == 0) return 0;
    IMAGE_SECTION_HEADER *s = &pe->sections[0];

    for (int i = 0; i < 8; ++i) {
        if (s->Name[i] & 0x80)
            return 1;
    }
    return 0;
}

static int check_sections_empty_name(ParsedPe *pe)
{
    if (pe->num_sections == 0) return 0;
    IMAGE_SECTION_HEADER *s = &pe->sections[0];

    for (int i = 0; i < 8; ++i) {
        if (s->Name[i] != 0 && s->Name[i] != ' ')
            return 0;
    }
    return 1;
}

static int check_sections_impossible_flags(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    uint32_t c = text->Characteristics;
    return (c & IMAGE_SCN_MEM_DISCARDABLE) != 0 &&
           (c & IMAGE_SCN_MEM_EXECUTE) != 0 &&
           (c & IMAGE_SCN_MEM_READ) != 0 &&
           (c & IMAGE_SCN_MEM_WRITE) != 0;
}

static int check_sections_raw_misaligned(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    uint32_t fa = pe->nt->OptionalHeader.FileAlignment;
    uint32_t raw = text->PointerToRawData;

    return raw == 0x410 && (raw % fa) != 0;
}

static int check_sections_overlap_headers(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;
    uint32_t raw = text->PointerToRawData;

    return raw == 0x200 && raw < soh;
}

static int check_sections_zero_length(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    return text->Misc.VirtualSize == 0 &&
           text->SizeOfRawData == 0;
}

static int check_sections_raw_overlap(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!text || !rdata) return 0;

    uint32_t t_start = text->PointerToRawData;
    uint32_t t_end = t_start + text->SizeOfRawData;
    uint32_t r_start = rdata->PointerToRawData;
    uint32_t r_end = r_start + rdata->SizeOfRawData;

    return t_start == 0x400 &&
           text->SizeOfRawData == 0x200 &&
           r_start == 0x500 &&
           rdata->SizeOfRawData == 0x200 &&
           t_start < r_end && r_start < t_end;
}

static int check_sections_virtual_overlap(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!text || !rdata) return 0;

    uint32_t t_start = text->VirtualAddress;
    uint32_t t_end = t_start + text->Misc.VirtualSize;
    uint32_t r_start = rdata->VirtualAddress;
    uint32_t r_end = r_start + rdata->Misc.VirtualSize;

    return t_start == 0x1000 &&
           r_start == 0x1800 &&
           t_start < r_end && r_start < t_end;
}

static int check_sections_out_of_order_raw(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!text || !rdata) return 0;

    return text->PointerToRawData == 0x600 &&
           rdata->PointerToRawData == 0x400 &&
           rdata->PointerToRawData < text->PointerToRawData;
}

static int check_sections_out_of_order_virtual(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!text || !rdata) return 0;

    return text->VirtualAddress == 0x2000 &&
           rdata->VirtualAddress == 0x1000 &&
           rdata->VirtualAddress < text->VirtualAddress;
}

static int check_sections_negative_fields(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    return text->VirtualAddress == 0xFFFFFFFFu &&
           text->PointerToRawData == 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------
// 3. Optional header fixtures
// ---------------------------------------------------------------------

static int check_opt_size_of_image_too_small(ParsedPe *pe)
{
    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;
    return soi == 0x2000;
}

static int check_opt_size_of_headers_misaligned(ParsedPe *pe)
{
    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;
    uint32_t fa = pe->nt->OptionalHeader.FileAlignment;

    return soh == 0x300 && (soh % fa) != 0;
}

static int check_opt_size_of_headers_too_small(ParsedPe *pe)
{
    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;
    return soh == 0x100;
}

static int check_opt_section_alignment_invalid(ParsedPe *pe)
{
    uint32_t sa = pe->nt->OptionalHeader.SectionAlignment;
    return sa == 0x180;
}

static int check_opt_file_alignment_invalid(ParsedPe *pe)
{
    uint32_t fa = pe->nt->OptionalHeader.FileAlignment;
    return fa == 0x300;
}

static int check_opt_size_fields_too_small(ParsedPe *pe)
{
    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;
    return soi == 0x1000;
}

static int check_opt_image_base_misaligned(ParsedPe *pe)
{
    uint32_t ib = pe->nt->OptionalHeader.ImageBase;
    return ib == 0x401234;
}

static int check_opt_num_dirs_invalid(ParsedPe *pe)
{
    uint32_t n = pe->nt->OptionalHeader.NumberOfRvaAndSizes;
    return n == 20;
}

static int check_opt_num_dirs_too_small(ParsedPe *pe)
{
    uint32_t n = pe->nt->OptionalHeader.NumberOfRvaAndSizes;
    if (n != 1) return 0;

    IMAGE_DATA_DIRECTORY *d = pe->nt->OptionalHeader.DataDirectory;
    return d[0].VirtualAddress == 0x1000 &&
           d[0].Size == 0x20;
}

static int check_opt_size_of_image_misaligned(ParsedPe *pe)
{
    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;
    return soi == 0x1800;
}

// ---------------------------------------------------------------------
// 4. Data directory fixtures (RVA graph)
// ---------------------------------------------------------------------

static IMAGE_DATA_DIRECTORY *ddir0(ParsedPe *pe, int idx)
{
    return dd(pe, idx);
}

static int check_ddir_negative_rva(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0xFFFFFFFFu &&
           d->Size == 0x20;
}

static int check_ddir_negative_size(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0xFFFFFFFFu;
}

static int check_ddir_zero_zero(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0 &&
           d->Size == 0;
}

static int check_ddir_zero_rva_nonzero_size(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0 &&
           d->Size == 0x40;
}

static int check_ddir_zero_size_nonzero_rva(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0;
}

static int check_ddir_in_headers(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;

    return d->VirtualAddress == 0x200 &&
           d->Size == 0x40 &&
           d->VirtualAddress < soh;
}

static int check_ddir_out_of_range(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;
    uint32_t end = d->VirtualAddress + d->Size;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x200 &&
           end > soi;
}

static int check_ddir_raw_mismatch(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0x1100 &&
           d->Size == 0x800;
}

static int check_ddir_in_overlay(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress == soi + 0x100 &&
           d->Size == 0x40 &&
           d->VirtualAddress >= soi;
}

static int check_ddir_not_mapped(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0x5000 &&
           d->Size == 0x40;
}

static int check_ddir_spans_sections(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = ddir0(pe, 0);
    if (!d) return 0;

    return d->VirtualAddress == 0x1F00 &&
           d->Size == 0x200;
}

static int check_ddir_overlap(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d0 = ddir0(pe, 0);
    IMAGE_DATA_DIRECTORY *d1 = ddir0(pe, 1);
    if (!d0 || !d1) return 0;

    int first = (d0->VirtualAddress == 0x2000 && d0->Size == 0x200);
    int second = (d1->VirtualAddress == 0x2100 && d1->Size == 0x200);

    return first && second;
}

// ---------------------------------------------------------------------
// 5. TLS fixtures
// ---------------------------------------------------------------------

static int check_tls_negative_rva(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    return tls->VirtualAddress == 0xFFFFFFFFu &&
           tls->Size == 0xFFFFFFFFu;
}

static int check_tls_directory_in_headers(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;

    return tls->VirtualAddress == 0x200 &&
           tls->Size == 0x40 &&
           tls->VirtualAddress < soh;
}

static int check_tls_directory_in_overlay(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return tls->VirtualAddress >= soi &&
           tls->Size == 0x40;
}

static int check_tls_directory_not_mapped(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    return tls->VirtualAddress == 0x5000 &&
           tls->Size == 0x40;
}

static int check_tls_directory_spans_sections(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    return tls->VirtualAddress == 0x1F00 &&
           tls->Size == 0x100;
}

static int check_tls_callback_zero_length_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = sec_by_name(pe, ".text");
    if (!text) return 0;

    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t cb_rva = tls->VirtualAddress; // assuming callbacks RVA stored here in your loader

    return text->Misc.VirtualSize == 0 &&
           cb_rva == text->VirtualAddress;
}

static int check_tls_callback_in_writable_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!rdata) return 0;

    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t cb_rva = tls->VirtualAddress;

    return (rdata->Characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
           cb_rva == rdata->VirtualAddress + 0x10;
}

static int check_tls_callback_in_discardable_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *rdata = sec_by_name(pe, ".rdata");
    if (!rdata) return 0;

    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t cb_rva = tls->VirtualAddress;

    return (rdata->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 &&
           cb_rva == rdata->VirtualAddress + 0x20;
}

static int check_tls_callback_in_rsrc(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *rsrc = sec_by_name(pe, ".rsrc");
    if (!rsrc) return 0;

    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    uint32_t cb_rva = tls->VirtualAddress;

    return cb_rva == rsrc->VirtualAddress + 0x30;
}

static int check_tls_directory_synthetic_range(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *tls = dd(pe, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls) return 0;

    return tls->VirtualAddress == 0x1000 &&
           tls->Size == 0x90000000u;
}

// ---------------------------------------------------------------------
// 6. Signature fixtures
// ---------------------------------------------------------------------

static IMAGE_DATA_DIRECTORY *sig_dir(ParsedPe *pe, int idx)
{
    return dd(pe, idx);
}

static int check_sig_negative_offset(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0xFFFFFFFFu &&
           d->Size == 0x100;
}

static int check_sig_negative_size(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 0xFFFFFFFFu;
}

static int check_sig_offset_overflow(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    uint64_t off = d->VirtualAddress;
    uint64_t sz = d->Size;
    uint64_t end = off + sz;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x300 &&
           end > soi;
}

static int check_sig_in_headers(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    uint32_t soh = pe->nt->OptionalHeader.SizeOfHeaders;

    return d->VirtualAddress == 0x200 &&
           d->Size == 0x80 &&
           d->VirtualAddress < soh;
}

static int check_sig_overlaps_text(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return range_overlap(d->VirtualAddress, d->Size, 0x400, 0x200);
}

static int check_sig_overlaps_rdata(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return range_overlap(d->VirtualAddress, d->Size, 0x600, 0x200);
}

static int check_sig_overlaps_reloc(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return range_overlap(d->VirtualAddress, d->Size, 0xA00, 0x200);
}

static int check_sig_entirely_in_overlay(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress == soi + 0x100 &&
           d->Size == 0x200 &&
           d->VirtualAddress >= soi;
}

static int check_sig_invalid_revision(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 4 &&
           d->Size < 8;
}

static int check_sig_invalid_type(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0x3100 &&
           d->Size == 6 &&
           d->Size < 8;
}

static int check_sig_missing_fields(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0x3200 &&
           d->Size == 2 &&
           d->Size < 8;
}

static int check_sig_multiple_mixed_validity(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d1 = sig_dir(pe, 4);
    IMAGE_DATA_DIRECTORY *d2 = sig_dir(pe, 5);
    if (!d1 || !d2) return 0;

    int first_validish = (d1->VirtualAddress == 0x3000 &&
                           d1->Size == 0x80 &&
                           d1->Size >= 8);
    int second_invalid = (d2->VirtualAddress == 0x3080 &&
                           d2->Size == 4 &&
                           d2->Size < 8);

    return first_validish && second_invalid;
}

static int check_sig_exactly_at_eof(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    uint64_t off = d->VirtualAddress;
    uint64_t sz = d->Size;
    uint64_t end = off + sz;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x100 &&
           end == soi;
}

static int check_sig_one_byte_past_eof(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    uint64_t off = d->VirtualAddress;
    uint64_t sz = d->Size;
    uint64_t end = off + sz;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x101 &&
           end == (uint64_t)soi + 1;
}

static int check_sig_zero_length(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = sig_dir(pe, 4);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 0 &&
           d->Size < 8;
}

// ---------------------------------------------------------------------
// 7. Resource fixtures
// ---------------------------------------------------------------------

static IMAGE_DATA_DIRECTORY *res_dir(ParsedPe *pe)
{
    return dd(pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

static IMAGE_SECTION_HEADER *rsrc_section(ParsedPe *pe)
{
    return find_section_by_name(pe, ".rsrc");
}

static int rva_in_rsrc(ParsedPe *pe, uint32_t rva)
{
    IMAGE_SECTION_HEADER *s = rsrc_section(pe);
    if (!s) return 0;
    return (rva >= s->VirtualAddress &&
            rva < s->VirtualAddress + s->Misc.VirtualSize);
}

static int rva_range_in_rsrc(ParsedPe *pe, uint32_t rva, uint32_t size)
{
    IMAGE_SECTION_HEADER *s = rsrc_section(pe);
    if (!s) return 0;
    uint32_t start = rva;
    uint32_t end = rva + size;
    uint32_t s_start = s->VirtualAddress;
    uint32_t s_end = s_start + s->Misc.VirtualSize;
    return (start >= s_start && end <= s_end);
}

static int check_res_dir_zero_length(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    IMAGE_SECTION_HEADER *rsrc = rsrc_section(pe);
    if (!rsrc) return 0;

    return d->VirtualAddress == rsrc->VirtualAddress &&
           d->Size == 0;
}

static int check_res_dir_loop(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    IMAGE_SECTION_HEADER *rsrc = rsrc_section(pe);
    if (!rsrc) return 0;

    return d->VirtualAddress == rsrc->VirtualAddress + 0x10 &&
           d->Size == 0x20 &&
           rsrc->Misc.VirtualSize == 0x20;
}

static int check_res_dir_partially_outside_rsrc(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x200 &&
           !rva_range_in_rsrc(pe, d->VirtualAddress, d->Size);
}

static int check_res_entry_out_of_bounds(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x5000 &&
           d->Size == 0x40 &&
           !rva_in_rsrc(pe, d->VirtualAddress);
}

static int check_res_data_zero_size(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    IMAGE_SECTION_HEADER *rsrc = rsrc_section(pe);
    if (!rsrc) return 0;

    return d->VirtualAddress == rsrc->VirtualAddress + 0x100 &&
           d->Size == 0;
}

static int check_res_data_partially_outside_rsrc(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x3F00 &&
           d->Size == 0x300 &&
           !rva_range_in_rsrc(pe, d->VirtualAddress, d->Size);
}

static int check_res_data_out_of_file_bounds(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;
    uint32_t end = d->VirtualAddress + d->Size;

    return d->VirtualAddress == 0x3E00 &&
           d->Size == 0x500 &&
           end > soi;
}

static int check_res_data_overlaps_overlay(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    uint32_t soi = pe->nt->OptionalHeader.SizeOfImage;

    return d->VirtualAddress >= soi &&
           d->Size == 0x200;
}

static int check_res_data_overlaps_text(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x450 &&
           d->Size == 0x200 &&
           range_overlap(d->VirtualAddress, d->Size, 0x400, 0x200);
}

static int check_res_data_overlaps_rdata(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x650 &&
           d->Size == 0x200 &&
           range_overlap(d->VirtualAddress, d->Size, 0x600, 0x200);
}

static int check_res_string_table_outside_rsrc(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = res_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x5000 &&
           d->Size == 0x80 &&
           !rva_in_rsrc(pe, d->VirtualAddress);
}

// ---------------------------------------------------------------------
// 8. Entropy fixtures
// ---------------------------------------------------------------------

static IMAGE_DATA_DIRECTORY *entropy_dir(ParsedPe *pe)
{
    return dd(pe, 10);
}

/* Section-based entropy */

static int check_entropy_nan_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 0;
}

static int check_entropy_inf_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 0xFFFFFFFFu;
}

static int check_entropy_negative_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 0xFFFFFFFFu;
}

static int check_entropy_small_section_high(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 100;
}

static int check_entropy_small_section_low(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 200;
}

static int check_entropy_zero_length_section(ParsedPe *pe)
{
    IMAGE_SECTION_HEADER *text = find_section_by_name(pe, ".text");
    if (!text) return 0;

    return text->SizeOfRawData == 0;
}

/* Overlay entropy */

static int check_entropy_overlay_exact_threshold(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *sec = dd(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (!sec) return 0;

    return sec->Size == 1024;
}

static int check_entropy_overlay_just_below_threshold(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *sec = dd(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (!sec) return 0;

    return sec->Size == 1023;
}

static int check_entropy_overlay_nan(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *sec = dd(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (!sec) return 0;

    return sec->Size == 0;
}

static int check_entropy_overlay_negative(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *sec = dd(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (!sec) return 0;

    return sec->Size == 0x1000;
}

/* Region entropy (directory[10]) */

static int check_entropy_region_missing_fields(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0;
}

static int check_entropy_region_nan(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 0;
}

static int check_entropy_region_negative(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 0x1000;
}

static int check_entropy_region_small_size(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x3000 &&
           d->Size == 100;
}

/* Uniform entropy (directory[10]) */

static int check_entropy_uniform_nan(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0;
}

static int check_entropy_uniform_inf(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0x2000;
}

static int check_entropy_uniform_negative(ParsedPe *pe)
{
    IMAGE_DATA_DIRECTORY *d = entropy_dir(pe);
    if (!d) return 0;

    return d->VirtualAddress == 0x2000 &&
           d->Size == 0x1000;
}

// ---------------------------------------------------------------------
// Fixture mapping
// ---------------------------------------------------------------------

typedef int (*check_fn)(ParsedPe *);

typedef struct {
    const char *name;
    check_fn fn;
} FixtureCheck;

static FixtureCheck FIXTURES[] = {
    /* 1. Entrypoint */
    { "entrypoint_zero", check_entrypoint_zero },
    { "entrypoint_negative", check_entrypoint_negative },
    { "entrypoint_in_headers", check_entrypoint_in_headers },
    { "entrypoint_gap_between_sections", check_entrypoint_gap_between_sections },
    { "entrypoint_non_exec_section", check_entrypoint_non_exec_section },
    { "entrypoint_rsrc", check_entrypoint_rsrc },
    { "entrypoint_discardable", check_entrypoint_discardable },
    { "entrypoint_zero_length_section", check_entrypoint_zero_length_section },
    { "entrypoint_beyond_virtual_size", check_entrypoint_beyond_virtual_size },
    { "entrypoint_in_overlay", check_entrypoint_in_overlay },

    /* 2. Sections */
    { "sections_rwx", check_sections_rwx },
    { "sections_code_not_exec", check_sections_code_not_exec },
    { "sections_codelike_not_exec", check_sections_codelike_not_exec },
    { "sections_non_ascii_name", check_sections_non_ascii_name },
    { "sections_empty_name", check_sections_empty_name },
    { "sections_impossible_flags", check_sections_impossible_flags },
    { "sections_raw_misaligned", check_sections_raw_misaligned },
    { "sections_overlap_headers", check_sections_overlap_headers },
    { "sections_zero_length", check_sections_zero_length },
    { "sections_raw_overlap", check_sections_raw_overlap },
    { "sections_virtual_overlap", check_sections_virtual_overlap },
    { "sections_out_of_order_raw", check_sections_out_of_order_raw },
    { "sections_out_of_order_virtual", check_sections_out_of_order_virtual },
    { "sections_negative_fields", check_sections_negative_fields },

    /* 3. Optional header */
    { "opt_size_of_image_too_small", check_opt_size_of_image_too_small },
    { "opt_size_of_headers_misaligned", check_opt_size_of_headers_misaligned },
    { "opt_size_of_headers_too_small", check_opt_size_of_headers_too_small },
    { "opt_section_alignment_invalid", check_opt_section_alignment_invalid },
    { "opt_file_alignment_invalid", check_opt_file_alignment_invalid },
    { "opt_size_fields_too_small", check_opt_size_fields_too_small },
    { "opt_image_base_misaligned", check_opt_image_base_misaligned },
    { "opt_num_dirs_invalid", check_opt_num_dirs_invalid },
    { "opt_num_dirs_too_small", check_opt_num_dirs_too_small },
    { "opt_size_of_image_misaligned", check_opt_size_of_image_misaligned },

    /* 4. Data directory */
    { "ddir_negative_rva", check_ddir_negative_rva },
    { "ddir_negative_size", check_ddir_negative_size },
    { "ddir_zero_zero", check_ddir_zero_zero },
    { "ddir_zero_rva_nonzero_size", check_ddir_zero_rva_nonzero_size },
    { "ddir_zero_size_nonzero_rva", check_ddir_zero_size_nonzero_rva },
    { "ddir_in_headers", check_ddir_in_headers },
    { "ddir_out_of_range", check_ddir_out_of_range },
    { "ddir_raw_mismatch", check_ddir_raw_mismatch },
    { "ddir_in_overlay", check_ddir_in_overlay },
    { "ddir_not_mapped", check_ddir_not_mapped },
    { "ddir_spans_sections", check_ddir_spans_sections },
    { "ddir_overlap", check_ddir_overlap },

    /* 5. TLS */
    { "tls_negative_rva", check_tls_negative_rva },
    { "tls_directory_in_headers", check_tls_directory_in_headers },
    { "tls_directory_in_overlay", check_tls_directory_in_overlay },
    { "tls_directory_not_mapped", check_tls_directory_not_mapped },
    { "tls_directory_spans_sections", check_tls_directory_spans_sections },
    { "tls_callback_zero_length_section",check_tls_callback_zero_length_section },
    { "tls_callback_in_writable_section",check_tls_callback_in_writable_section },
    { "tls_callback_in_discardable_section",check_tls_callback_in_discardable_section },
    { "tls_callback_in_rsrc", check_tls_callback_in_rsrc },
    { "tls_directory_synthetic_range", check_tls_directory_synthetic_range },

    /* 6. Signature */
    { "sig_negative_offset", check_sig_negative_offset },
    { "sig_negative_size", check_sig_negative_size },
    { "sig_offset_overflow", check_sig_offset_overflow },
    { "sig_in_headers", check_sig_in_headers },
    { "sig_overlaps_text", check_sig_overlaps_text },
    { "sig_overlaps_rdata", check_sig_overlaps_rdata },
    { "sig_overlaps_reloc", check_sig_overlaps_reloc },
    { "sig_entirely_in_overlay", check_sig_entirely_in_overlay },
    { "sig_invalid_revision", check_sig_invalid_revision },
    { "sig_invalid_type", check_sig_invalid_type },
    { "sig_missing_fields", check_sig_missing_fields },
    { "sig_multiple_mixed_validity", check_sig_multiple_mixed_validity },
    { "sig_exactly_at_eof", check_sig_exactly_at_eof },
    { "sig_one_byte_past_eof", check_sig_one_byte_past_eof },
    { "sig_zero_length", check_sig_zero_length },

    /* 7. Resource */
    { "res_dir_zero_length", check_res_dir_zero_length },
    { "res_dir_loop", check_res_dir_loop },
    { "res_dir_partially_outside_rsrc", check_res_dir_partially_outside_rsrc },
    { "res_entry_out_of_bounds", check_res_entry_out_of_bounds },
    { "res_data_zero_size", check_res_data_zero_size },
    { "res_data_partially_outside_rsrc", check_res_data_partially_outside_rsrc },
    { "res_data_out_of_file_bounds", check_res_data_out_of_file_bounds },
    { "res_data_overlaps_overlay", check_res_data_overlaps_overlay },
    { "res_data_overlaps_text", check_res_data_overlaps_text },
    { "res_data_overlaps_rdata", check_res_data_overlaps_rdata },
    { "res_string_table_outside_rsrc", check_res_string_table_outside_rsrc },

    /* 8. Entropy */
    { "entropy_nan_section", check_entropy_nan_section },
    { "entropy_inf_section", check_entropy_inf_section },
    { "entropy_negative_section", check_entropy_negative_section },
    { "entropy_small_section_high", check_entropy_small_section_high },
    { "entropy_small_section_low", check_entropy_small_section_low },
    { "entropy_zero_length_section", check_entropy_zero_length_section },
    { "entropy_overlay_exact_threshold", check_entropy_overlay_exact_threshold },
    { "entropy_overlay_just_below_threshold", check_entropy_overlay_just_below_threshold },
    { "entropy_overlay_nan", check_entropy_overlay_nan },
    { "entropy_overlay_negative", check_entropy_overlay_negative },
    { "entropy_region_missing_fields", check_entropy_region_missing_fields },
    { "entropy_region_nan", check_entropy_region_nan },
    { "entropy_region_negative", check_entropy_region_negative },
    { "entropy_region_small_size", check_entropy_region_small_size },
    { "entropy_uniform_nan", check_entropy_uniform_nan },
    { "entropy_uniform_inf", check_entropy_uniform_inf },
    { "entropy_uniform_negative", check_entropy_uniform_negative },
};

static const size_t FIXTURE_COUNT = sizeof(FIXTURES) / sizeof(FIXTURES[0]);

// ---------------------------------------------------------------------
// Name extraction from filename
// "out/fixture_090_entropy_overlay_nan.full.exe"
// → "entropy_overlay_nan"
// ---------------------------------------------------------------------

static const char *basename(const char *path)
{
    const char *p = strrchr(path, '\\');
    if (!p) p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static void extract_fixture_name(const char *filename, char *out, size_t out_sz)
{
    // expect "fixture_XXX_name.full.exe"
    const char *base = basename(filename);

    const char *p = strstr(base, "fixture_");
    if (!p) {
        strncpy(out, base, out_sz - 1);
        out[out_sz - 1] = 0;
        return;
    }
    p += strlen("fixture_");

    // skip numeric index and underscore
    while (*p >= '0' && *p <= '9') p++;
    if (*p == '_') p++;

    const char *end = strstr(p, ".full.exe");
    if (!end) end = p + strlen(p);

    size_t len = (size_t)(end - p);
    if (len >= out_sz) len = out_sz - 1;

    memcpy(out, p, len);
    out[len] = 0;
}

static check_fn find_checker(const char *fixture_name)
{
    for (size_t i = 0; i < FIXTURE_COUNT; ++i) {
        if (strcmp(FIXTURES[i].name, fixture_name) == 0)
            return FIXTURES[i].fn;
    }
    return NULL;
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: checker.exe out/fixture_XXX_*.exe ...\n");
        return 1;
    }

    int overall_fail = 0;

    for (int i = 1; i < argc; ++i) {
        const char *path = argv[i];
        char fname[256];
        extract_fixture_name(path, fname, sizeof(fname));

        check_fn fn = find_checker(fname);
        if (!fn) {
            fprintf(stderr, "[SKIP] %s (no checker for fixture name '%s')\n", path, fname);
            continue;
        }

        ParsedPe pe;
        if (!load_pe(path, &pe)) {
            fprintf(stderr, "[FAIL] %s (%s): could not parse PE\n", path, fname);
            overall_fail = 1;
            continue;
        }

        int ok = fn(&pe);
        free_pe(&pe);

        if (ok) {
            printf("[PASS] %s (%s)\n", path, fname);
        } else {
            printf("[FAIL] %s (%s)\n", path, fname);
            overall_fail = 1;
        }
    }

    return overall_fail ? 1 : 0;
}
