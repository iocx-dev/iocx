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
    FILE *f = fopen("franken_malformed_pe.full.exe", "wb");
    if (!f) {
        perror("franken_malformed_pe.full.exe");
        return 1;
    }

    // --- DOS + stub ---
    DOS dos = {0};
    dos.e_magic = 0x5A4D;
    dos.e_lfanew = 0x100; // push PE header further down
    w(f, &dos, sizeof(dos));

    // crude stub
    for (int i = 0; i < 0x80; i++) fputc(0x90, f);

    pad(f, dos.e_lfanew);

    // --- PE signature ---
    PE_SIG sig = {0x00004550};
    w(f, &sig, sizeof(sig));

    // --- File header ---
    FILE_HDR fh = {0};
    fh.Machine = 0x8664;
    fh.NumberOfSections = 2; // make them overlap
    fh.SizeOfOptionalHeader = sizeof(OPT64);
    fh.Characteristics = 0x0002;
    w(f, &fh, sizeof(fh));

    // --- Optional header (intentionally inconsistent) ---
    OPT64 opt = {0};
    opt.Magic = 0x20B;
    opt.AddressOfEntryPoint = 0x1100; // inside first section
    opt.BaseOfCode = 0x1000;
    opt.ImageBase = 0x140000000ULL;

    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;

    opt.SizeOfCode = 0x100; // too small for sections
    opt.SizeOfInitializedData = 0x10;
    opt.SizeOfUninitializedData = 0;

    opt.SizeOfHeaders = 0x200;
    opt.SizeOfImage = 0x2000; // too small for claim

    opt.Subsystem = 3;
    opt.NumDirs = 16;

    // Broken import directory: points into overlapping region
    opt.DataDir[1].VirtualAddress = 0x1800; // IMAGE_DIRECTORY_ENTRY_IMPORT
    opt.DataDir[1].Size = 0x400;

    // Another directory pointing out of range
    opt.DataDir[2].VirtualAddress = 0xFFFFFFF0;
    opt.DataDir[2].Size = 0x100;

    w(f, &opt, sizeof(opt));

    // --- Section headers (overlapping) ---

    // .text at 0x1000, raw at 0x200
    SECT text = {0};
    memcpy(text.Name, ".text", 5);
    text.VirtualAddress = 0x1000;
    text.VirtualSize = 0x800;
    text.PointerToRawData = 0x200;
    text.SizeOfRawData = 0x600;
    text.Characteristics = 0x60000020; // code | exec | read

    // .rdata overlapping .text in both RVA and raw
    SECT rdata = {0};
    memcpy(rdata.Name, ".rdata", 6);
    rdata.VirtualAddress = 0x1400; // inside .text range
    rdata.VirtualSize = 0x800;
    rdata.PointerToRawData = 0x300; // inside .text raw range
    rdata.SizeOfRawData = 0x600;
    rdata.Characteristics = 0x40000040; // read | initialized data

    w(f, &text, sizeof(text));
    w(f, &rdata, sizeof(rdata));

    // --- Section data (intentionally conflicting) ---

    // Fill from 0x200 with pattern A
    pad(f, 0x200);
    for (int i = 0; i < 0x600; i++) fputc(0xAA, f);

    // Now seek into the middle (overlap region) and write pattern B
    fseek(f, 0x300, SEEK_SET);
    for (int i = 0; i < 0x400; i++) fputc(0xBB, f);

    // Minimal "code" at entrypoint RVA 0x1100 (raw offset inside .text)
    long entry_raw = 0x200 + (0x1100 - 0x1000);
    fseek(f, entry_raw, SEEK_SET);
    unsigned char code[8] = {0xC3}; // ret
    w(f, code, sizeof(code));

    fclose(f);
    return 0;
}
