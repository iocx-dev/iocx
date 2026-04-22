#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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
    int32_t e_lfanew;
} DOS;

typedef struct {
    uint32_t Signature;
} PE_SIG;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} FILE_HDR;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DIR;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOS;
    uint16_t MinorOS;
    uint16_t MajorImg;
    uint16_t MinorImg;
    uint16_t MajorSub;
    uint16_t MinorSub;
    uint32_t Win32Ver;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllChars;
    uint64_t StackRes;
    uint64_t StackCom;
    uint64_t HeapRes;
    uint64_t HeapCom;
    uint32_t LoaderFlags;
    uint32_t NumDirs;
    DIR DataDir[16];
} OPT64;

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
} SECT;

#pragma pack(pop)

static void w(FILE *f, const void *b, size_t s) {
    if (fwrite(b, 1, s, f) != s) {
        perror("fwrite");
        exit(1);
    }
}

static void pad(FILE *f, long t) {
    while (ftell(f) < t) fputc(0, f);
}

int main(void) {
    FILE *f = fopen("franken_malformed_pe.generated.exe", "wb");
    if (!f) {
        perror("franken_malformed_pe.generated.exe");
        return 1;
    }

    // --- DOS + stub ---
    DOS dos = {0};
    dos.e_magic = 0x5A4D; // "MZ"
    dos.e_lfanew = 0x100; // PE header offset
    w(f, &dos, sizeof(dos));

    // crude stub
    for (int i = 0; i < 0x80; i++) fputc(0x90, f);

    pad(f, dos.e_lfanew);

    // --- PE signature ---
    PE_SIG sig = {0x00004550}; // "PE\0\0"
    w(f, &sig, sizeof(sig));

    // --- File header ---
    FILE_HDR fh = {0};
    fh.Machine = 0x8664; // AMD64
    fh.NumberOfSections = 4; // multiple sections to play with
    fh.SizeOfOptionalHeader = sizeof(OPT64);
    fh.Characteristics = 0x0002; // executable image
    w(f, &fh, sizeof(fh));

    // --- Optional header (intentionally inconsistent) ---
    OPT64 opt = {0};
    opt.Magic = 0x20B; // PE32+
    opt.MajorLinkerVersion = 14;
    opt.MinorLinkerVersion = 44;

    opt.AddressOfEntryPoint = 0x3000; // OUTSIDE any section -> entrypoint_out_of_bounds
    opt.BaseOfCode = 0x1000;
    opt.ImageBase = 0x140000000ULL;

    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;

    opt.SizeOfCode = 0x100; // too small vs sections
    opt.SizeOfInitializedData = 0x10;
    opt.SizeOfUninitializedData = 0;

    opt.MajorOS = 6;
    opt.MinorOS = 0;
    opt.MajorImg = 0;
    opt.MinorImg = 0;
    opt.MajorSub = 6;
    opt.MinorSub = 0;

    opt.SizeOfHeaders = 0x200;
    opt.SizeOfImage = 0x2000; // smaller than max section end -> optional_header_inconsistent_size

    opt.Subsystem = 3; // CUI
    opt.NumDirs = 16;

    // Directories:
    // 0: EXPORT (empty)
    opt.DataDir[0].VirtualAddress = 0;
    opt.DataDir[0].Size = 0;

    // 1: IMPORT – RVA outside any section -> import_rva_invalid + data_directory_out_of_range
    opt.DataDir[1].VirtualAddress = 0x5000;
    opt.DataDir[1].Size = 0x200;

    // 2: RESOURCE – zero RVA but non-zero size -> data_directory_zero_rva_nonzero_size
    opt.DataDir[2].VirtualAddress = 0x0000;
    opt.DataDir[2].Size = 0x100;

    // 3: EXCEPTION – inside a section (valid, control case)
    opt.DataDir[3].VirtualAddress = 0x1800;
    opt.DataDir[3].Size = 0x200;

    // others left zeroed

    w(f, &opt, sizeof(opt));

    // --- Section headers ---

    // .text at 0x1000, raw at 0x200 (aligned)
    SECT text = {0};
    memcpy(text.Name, ".text", 5);
    text.VirtualAddress = 0x1000;
    text.VirtualSize = 0x800;
    text.PointerToRawData = 0x200;
    text.SizeOfRawData = 0x600;
    text.Characteristics = 0x60000020; // code | exec | read

    // .rdata overlapping .text in RVA and raw -> section_overlap
    SECT rdata = {0};
    memcpy(rdata.Name, ".rdata", 6);
    rdata.VirtualAddress = 0x1400; // inside .text range (0x1000–0x1800)
    rdata.VirtualSize = 0x800;
    rdata.PointerToRawData = 0x300; // inside .text raw range (0x200–0x800)
    rdata.SizeOfRawData = 0x600;
    rdata.Characteristics = 0x40000040; // read | initialized data

    // .data – non-overlapping but RAW MISALIGNED -> section_raw_misaligned
    SECT data = {0};
    memcpy(data.Name, ".data", 5);
    data.VirtualAddress = 0x2000;
    data.VirtualSize = 0x400;
    data.PointerToRawData = 0x950; // NOT multiple of 0x200
    data.SizeOfRawData = 0x300; // also not multiple of 0x200
    data.Characteristics = 0xC0000040; // read | write | initialized

    // .rsrc – high RVA to push max section end beyond SizeOfImage
    SECT rsrc = {0};
    memcpy(rsrc.Name, ".rsrc", 5);
    rsrc.VirtualAddress = 0x2800; // 0x2800 + 0x600 = 0x2E00 > SizeOfImage (0x2000)
    rsrc.VirtualSize = 0x600;
    rsrc.PointerToRawData = 0xC00; // aligned, just to have some data
    rsrc.SizeOfRawData = 0x600;
    rsrc.Characteristics = 0x40000040;

    w(f, &text, sizeof(text));
    w(f, &rdata, sizeof(rdata));
    w(f, &data, sizeof(data));
    w(f, &rsrc, sizeof(rsrc));

    // --- Section data ---

    // .text raw at 0x200
    pad(f, 0x200);
    for (int i = 0; i < 0x600; i++) fputc(0xAA, f);

    // Overwrite overlapping region for .rdata (0x300–0x700)
    fseek(f, 0x300, SEEK_SET);
    for (int i = 0; i < 0x400; i++) fputc(0xBB, f);

    // .data raw at 0x950 (misaligned)
    pad(f, 0x950);
    for (int i = 0; i < 0x300; i++) fputc(0xCC, f);

    // .rsrc raw at 0xC00
    pad(f, 0xC00);
    for (int i = 0; i < 0x600; i++) fputc(0xDD, f);

    // Minimal code at the (invalid) entrypoint RVA 0x3000:
    // we still drop a RET somewhere in file just to keep disassemblers happy,
    // but 0x3000 does not map to any section, so the EP mapping should fail.
    unsigned char code[1] = {0xC3}; // ret
    // place it arbitrarily in .text
    long entry_raw = 0x200 + (0x1100 - 0x1000);
    fseek(f, entry_raw, SEEK_SET);
    w(f, code, sizeof(code));

    fclose(f);
    return 0;
}
