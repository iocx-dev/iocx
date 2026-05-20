#include "pe_emit.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <errno.h>
#endif

/* PE constants */
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_FILE_HEADER 20
#define IMAGE_SIZEOF_OPTIONAL_HEADER 224
#define IMAGE_SIZEOF_NT_HEADERS (4 + IMAGE_SIZEOF_FILE_HEADER + IMAGE_SIZEOF_OPTIONAL_HEADER)
#define IMAGE_SIZEOF_SECTION_HEADER 40

/* Directory indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

/* Helpers */

static uint32_t align_up(uint32_t value, uint32_t align)
{
    if (align == 0) return value;
    uint32_t rem = value % align;
    return rem ? (value + (align - rem)) : value;
}

/* Minimal PE structures */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER_MIN;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER_MIN;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY_MIN;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_MIN DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32_MIN;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER_MIN FileHeader;
    IMAGE_OPTIONAL_HEADER32_MIN OptionalHeader;
} IMAGE_NT_HEADERS32_MIN;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER_MIN;

#pragma pack(pop)

/* Compute section raw layout based on FixtureSpec */
static void compute_section_layout(const FixtureSpec *f, uint32_t *section_raw_starts, uint32_t *section_raw_sizes, uint32_t *headers_size_out, uint32_t *file_size_out)
{
    uint32_t file_align = f->file_alignment ? f->file_alignment : 0x200;
    uint32_t sect_align = f->section_alignment ? f->section_alignment : 0x1000;
    uint32_t headers_size = align_up(f->size_of_headers ? f->size_of_headers : 0x400, file_align);
    uint32_t current_raw = headers_size;
    uint32_t max_raw_end = headers_size;

    for (size_t i = 0; i < f->section_count; ++i) {
        const SectionSpec *s = &f->sections[i];
        uint32_t raw_size = s->raw_size;
        if (raw_size == 0 && s->vs != 0) {
            raw_size = align_up(s->vs, file_align);
        }
        uint32_t raw_start = s->raw ? s->raw : current_raw;
        raw_start = align_up(raw_start, file_align);

        section_raw_starts[i] = raw_start;
        section_raw_sizes[i] = raw_size;

        if (raw_size) {
            uint32_t end = raw_start + raw_size;
            if (end > max_raw_end) max_raw_end = end;
        }
        current_raw = raw_start + raw_size;
    }

    uint32_t file_size = max_raw_end;
    if (f->overlay_size) {
        uint32_t overlay_start = align_up(file_size, file_align);
        file_size = overlay_start + f->overlay_size;
    }

    *headers_size_out = headers_size;
    *file_size_out = file_size;
}

/* Map RVA to raw offset using sections */
static int rva_to_raw(const FixtureSpec *f, const uint32_t *section_raw_starts, const uint32_t *section_raw_sizes, uint32_t rva, uint32_t *raw_out)
{
    for (size_t i = 0; i < f->section_count; ++i) {
        const SectionSpec *s = &f->sections[i];
        uint32_t va_start = s->va;
        uint32_t va_end = s->va + (s->vs ? s->vs : s->raw_size);
        if (rva >= va_start && rva < va_end) {
            uint32_t delta = rva - va_start;
            if (delta >= section_raw_sizes[i]) return 0;
            *raw_out = section_raw_starts[i] + delta;
            return 1;
        }
    }
    return 0;
}

/* Write little helper to ensure directory array is filled */
static void fill_directories(const FixtureSpec *f, IMAGE_OPTIONAL_HEADER32_MIN *opt)
{
    memset(opt->DataDirectory, 0, sizeof(opt->DataDirectory));

    int count = f->directory_count;
    if (count < 0) count = 0;
    if (count > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) count = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    for (int i = 0; i < count; ++i) {
        opt->DataDirectory[i].VirtualAddress = f->directories[i].rva;
        opt->DataDirectory[i].Size = f->directories[i].size;
    }
}

/* Main emitter */

int write_fixture_pe(const FixtureSpec *f, const char *path)
{
    uint32_t section_raw_starts[64] = {0};
    uint32_t section_raw_sizes[64] = {0};
    uint32_t headers_size = 0;
    uint32_t file_size = 0;

    if (f->section_count > 64) return -1;

    compute_section_layout(f, section_raw_starts, section_raw_sizes, &headers_size, &file_size);

    uint8_t *buf = (uint8_t *)calloc(1, file_size);
    if (!buf) return -1;

    /* DOS header */
    IMAGE_DOS_HEADER_MIN *dos = (IMAGE_DOS_HEADER_MIN *)buf;
    memset(dos, 0, sizeof(*dos));
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_cblp = 0x90;
    dos->e_cp = 3;
    dos->e_cparhdr = 4;
    dos->e_lfarlc = 0x40;
    dos->e_lfanew = 0x80;

    /* NT headers */
    IMAGE_NT_HEADERS32_MIN *nt = (IMAGE_NT_HEADERS32_MIN *)(buf + dos->e_lfanew);
    memset(nt, 0, sizeof(*nt));
    nt->Signature = IMAGE_NT_SIGNATURE;

    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.NumberOfSections = (uint16_t)f->section_count;
    nt->FileHeader.SizeOfOptionalHeader = IMAGE_SIZEOF_OPTIONAL_HEADER;
    nt->FileHeader.Characteristics = 0x0102; /* executable, 32-bit */

    IMAGE_OPTIONAL_HEADER32_MIN *opt = &nt->OptionalHeader;
    memset(opt, 0, sizeof(*opt));
    opt->Magic = 0x10B; /* PE32 */
    opt->AddressOfEntryPoint = f->entrypoint_rva;
    opt->ImageBase = f->image_base ? f->image_base : 0x400000;
    opt->SectionAlignment = f->section_alignment ? f->section_alignment : 0x1000;
    opt->FileAlignment = f->file_alignment ? f->file_alignment : 0x200;
    opt->SizeOfImage = f->size_of_image ? f->size_of_image : 0x4000;
    opt->SizeOfHeaders = headers_size;
    opt->Subsystem = 3; /* console */
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* Rough SizeOfCode / Data from sections */
    uint32_t size_code = 0, size_init = 0;
    for (size_t i = 0; i < f->section_count; ++i) {
        const SectionSpec *s = &f->sections[i];
        uint32_t raw_size = section_raw_sizes[i];
        if (raw_size == 0) continue;
        if (s->characteristics & 0x00000020) { /* CNT_CODE */
            size_code += raw_size;
        } else {
            size_init += raw_size;
        }
    }
    opt->SizeOfCode = size_code;
    opt->SizeOfInitializedData = size_init;

    fill_directories(f, opt);

    /* Section headers */
    IMAGE_SECTION_HEADER_MIN *sh = (IMAGE_SECTION_HEADER_MIN *)((uint8_t *)nt + IMAGE_SIZEOF_NT_HEADERS);
    for (size_t i = 0; i < f->section_count; ++i) {
        const SectionSpec *s = &f->sections[i];
        IMAGE_SECTION_HEADER_MIN *h = &sh[i];
        memset(h, 0, sizeof(*h));

        if (s->name) {
            size_t len = strlen(s->name);
            if (len > 8) len = 8;
            memcpy(h->Name, s->name, len);
        }

        h->VirtualAddress = s->va;
        h->VirtualSize = s->vs;
        h->SizeOfRawData = section_raw_sizes[i];
        h->PointerToRawData = section_raw_starts[i];
        h->Characteristics = s->characteristics;
    }

    /* Zero-fill section data; pattern overlay if requested */
    for (size_t i = 0; i < f->section_count; ++i) {
        uint32_t start = section_raw_starts[i];
        uint32_t size = section_raw_sizes[i];
        if (start + size > file_size) continue;
        memset(buf + start, 0x00, size);
    }

    /* Overlay */
    if (f->overlay_size) {
        uint32_t overlay_start = align_up(file_size - f->overlay_size, opt->FileAlignment);
        if (overlay_start + f->overlay_size <= file_size) {
            memset(buf + overlay_start, f->overlay_pattern, f->overlay_size);
        }
    }

    /* TLS directory (if any) – we just ensure RVA fields exist; data is zero */
    if (f->tls_start || f->tls_end || f->tls_callbacks) {
        uint32_t tls_dir_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        uint32_t tls_dir_raw = 0;
        if (tls_dir_rva && rva_to_raw(f, section_raw_starts, section_raw_sizes, tls_dir_rva, &tls_dir_raw)) {
            if (tls_dir_raw + 24 <= file_size) {
                uint32_t *p = (uint32_t *)(buf + tls_dir_raw);
                p[0] = (uint32_t)f->tls_start;
                p[1] = (uint32_t)f->tls_end;
                p[2] = (uint32_t)f->tls_callbacks;
            }
        }
    }

    /* Security directory is already described via directories[4] */

    /* Write file */
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        free(buf);
        return -1;
    }
    size_t written = fwrite(buf, 1, file_size, fp);
    fclose(fp);
    free(buf);

    return (written == file_size) ? 0 : -1;
}

/* Simple directory creation (best-effort, POSIX-ish) */
static void ensure_dir(const char *dir)
{
#ifdef _WIN32
    _mkdir(dir);
#else
    mkdir(dir, 0755);
#endif
}

int write_all_fixtures_pe(const char *dir)
{
    ensure_dir(dir);

    for (int i = 0; i < FIXTURE_COUNT; ++i) {
        const FixtureSpec *f = &FIXTURES[i];
        char path[512];
        snprintf(path, sizeof(path), "%s/fixture_%03d_%s.exe", dir, i, f->name ? f->name : "noname");
        if (write_fixture_pe(f, path) != 0) {
            return -1;
        }
    }
    return 0;
}
