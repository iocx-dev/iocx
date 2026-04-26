#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)

/* DOS header */
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

/* PE signature */
typedef struct { uint32_t Signature; } PE_SIG;

/* COFF header */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} FILE_HDR;

/* Data directory */
typedef struct { uint32_t VirtualAddress, Size; } DIR;

/* Optional header (PE32+) */
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

/* Section header */
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

/* Helpers */
static void w(FILE *f, const void *b, size_t s) {
    if (fwrite(b, 1, s, f) != s) exit(1);
}

static void pad(FILE *f, long t) {
    while (ftell(f) < t) fputc(0, f);
}

int main(void) {
    FILE *f = fopen("invalid_optional_header.full.exe", "wb");
    if (!f) return 1;

    /* ---------------- DOS HEADER ---------------- */
    DOS dos = {0};
    dos.e_magic = 0x5A4D; /* MZ */
    dos.e_lfanew = 0x80;
    w(f, &dos, sizeof(dos));
    pad(f, dos.e_lfanew);

    /* ---------------- PE SIGNATURE ---------------- */
    PE_SIG sig = {0x00004550};
    w(f, &sig, sizeof(sig));

    /* ---------------- FILE HEADER ---------------- */
    FILE_HDR fh = {0};
    fh.Machine = 0x8664;
    fh.NumberOfSections = 1;
    fh.SizeOfOptionalHeader = 0x70; /* WRONG: much smaller than OPT64 */
    fh.Characteristics = 0x2;
    w(f, &fh, sizeof(fh));

    /* ---------------- OPTIONAL HEADER ---------------- */
    OPT64 opt = {0};
    opt.Magic = 0x20B; /* PE32+ */

    /* INVALID optional-header fields */
    opt.AddressOfEntryPoint = 0x90000000; /* outside any section */
    opt.BaseOfCode = 0x1000;

    opt.ImageBase = 0x12345; /* INVALID: not 64K aligned */

    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x4000; /* INVALID: FileAlignment > SectionAlignment */

    opt.MajorOS = 10;
    opt.MinorOS = 0;
    opt.MajorImg = 0;
    opt.MinorImg = 0;
    opt.MajorSub = 99; /* INVALID: impossible subsystem version */
    opt.MinorSub = 99;

    opt.SizeOfImage = 0x200; /* INVALID: smaller than SizeOfHeaders */
    opt.SizeOfHeaders = 0x800;

    opt.Subsystem = 3;
    opt.NumDirs = 1; /* INVALID: too small */

    /* Write multiple directories anyway */
    opt.DataDir[0].VirtualAddress = 0x1000;
    opt.DataDir[0].Size = 0x200;

    opt.DataDir[1].VirtualAddress = 0xFFFFFFFF; /* INVALID RVA */
    opt.DataDir[1].Size = 0x100;

    opt.DataDir[2].VirtualAddress = 0x3000; /* beyond NumDirs */
    opt.DataDir[2].Size = 0x100;

    w(f, &opt, sizeof(opt));

    /* ---------------- SECTION TABLE ---------------- */
    SECT text = {0};
    memcpy(text.Name, ".text", 5);
    text.VirtualSize = 0x1000;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x200;
    text.Characteristics = 0x60000020;
    w(f, &text, sizeof(text));

    /* ---------------- SECTION DATA ---------------- */
    pad(f, 0x200);
    uint8_t code[16] = {0xC3};
    w(f, code, sizeof(code));

    fclose(f);
    return 0;
}
