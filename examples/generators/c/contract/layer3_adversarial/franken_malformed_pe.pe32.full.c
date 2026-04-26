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

/* PE32 optional header */
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
    uint32_t StackRes;
    uint32_t StackCom;
    uint32_t HeapRes;
    uint32_t HeapCom;
    uint32_t LoaderFlags;
    uint32_t NumDirs;
    DIR DataDir[16];
} OPT32;

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
    FILE *f = fopen("franken_malformed_pe.pe32.generated.exe", "wb");
    if (!f) {
        perror("franken_malformed_pe.pe32.generated.exe");
        return 1;
    }

    /* --- DOS + stub --- */
    DOS dos = {0};
    dos.e_magic = 0x5A4D; /* "MZ" */
    dos.e_lfanew = 0x100;
    w(f, &dos, sizeof(dos));

    for (int i = 0; i < 0x80; i++) fputc(0x90, f);
    pad(f, dos.e_lfanew);

    /* --- PE signature --- */
    PE_SIG sig = {0x00004550};
    w(f, &sig, sizeof(sig));

    /* --- File header --- */
    FILE_HDR fh = {0};
    fh.Machine = 0x014C; /* IMAGE_FILE_MACHINE_I386 */
    fh.NumberOfSections = 4;
    fh.SizeOfOptionalHeader = sizeof(OPT32);
    fh.Characteristics = 0x0002;
    w(f, &fh, sizeof(fh));

    /* --- Optional header (PE32, intentionally inconsistent) --- */
    OPT32 opt = {0};
    opt.Magic = 0x10B; /* PE32 */
    opt.MajorLinkerVersion = 14;
    opt.MinorLinkerVersion = 44;

    opt.AddressOfEntryPoint = 0x3000; /* outside any section */
    opt.BaseOfCode = 0x1000;
    opt.BaseOfData = 0x2000;
    opt.ImageBase = 0x00400000; /* valid-ish, but we’ll break other fields */

    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;

    opt.SizeOfCode = 0x100;
    opt.SizeOfInitializedData = 0x10;
    opt.SizeOfUninitializedData = 0;

    opt.MajorOS = 6;
    opt.MinorOS = 0;
    opt.MajorImg = 0;
    opt.MinorImg = 0;
    opt.MajorSub = 6;
    opt.MinorSub = 0;

    opt.SizeOfHeaders = 0x200;
    opt.SizeOfImage = 0x2000; /* smaller than max section end */

    opt.Subsystem = 3;
    opt.NumDirs = 16;

    /* Directories mirroring the PE32+ franken logic */
    /* 0: EXPORT (empty) */
    opt.DataDir[0].VirtualAddress = 0;
    opt.DataDir[0].Size = 0;

    /* 1: IMPORT – RVA outside any section */
    opt.DataDir[1].VirtualAddress = 0x5000;
    opt.DataDir[1].Size = 0x200;

    /* 2: RESOURCE – zero RVA but non-zero size */
    opt.DataDir[2].VirtualAddress = 0x0000;
    opt.DataDir[2].Size = 0x100;

    /* 3: EXCEPTION – inside a section (control case) */
    opt.DataDir[3].VirtualAddress = 0x1800;
    opt.DataDir[3].Size = 0x200;

    w(f, &opt, sizeof(opt));

    /* --- Section headers --- */

    /* .text at 0x1000, raw at 0x200 */
    SECT text = {0};
    memcpy(text.Name, ".text", 5);
    text.VirtualAddress = 0x1000;
    text.VirtualSize = 0x800;
    text.PointerToRawData = 0x200;
    text.SizeOfRawData = 0x600;
    text.Characteristics = 0x60000020;

    /* .rdata overlapping .text in RVA and raw */
    SECT rdata = {0};
    memcpy(rdata.Name, ".rdata", 6);
    rdata.VirtualAddress = 0x1400;
    rdata.VirtualSize = 0x800;
    rdata.PointerToRawData = 0x300;
    rdata.SizeOfRawData = 0x600;
    rdata.Characteristics = 0x40000040;

    /* .data – non-overlapping RVA, misaligned raw */
    SECT data = {0};
    memcpy(data.Name, ".data", 5);
    data.VirtualAddress = 0x2000;
    data.VirtualSize = 0x400;
    data.PointerToRawData = 0x950; /* not multiple of 0x200 */
    data.SizeOfRawData = 0x300; /* also not multiple of 0x200 */
    data.Characteristics = 0xC0000040;

    /* .rsrc – high RVA to push beyond SizeOfImage */
    SECT rsrc = {0};
    memcpy(rsrc.Name, ".rsrc", 5);
    rsrc.VirtualAddress = 0x2800; /* 0x2800 + 0x600 = 0x2E00 > 0x2000 */
    rsrc.VirtualSize = 0x600;
    rsrc.PointerToRawData = 0xC00;
    rsrc.SizeOfRawData = 0x600;
    rsrc.Characteristics = 0x40000040;

    w(f, &text, sizeof(text));
    w(f, &rdata, sizeof(rdata));
    w(f, &data, sizeof(data));
    w(f, &rsrc, sizeof(rsrc));

    /* --- Section data --- */

    /* .text raw at 0x200 */
    pad(f, 0x200);
    for (int i = 0; i < 0x600; i++) fputc(0xAA, f);

    /* Overwrite overlapping region for .rdata (0x300–0x700) */
    fseek(f, 0x300, SEEK_SET);
    for (int i = 0; i < 0x400; i++) fputc(0xBB, f);

    /* .data raw at 0x950 (misaligned) */
    pad(f, 0x950);
    for (int i = 0; i < 0x300; i++) fputc(0xCC, f);

    /* .rsrc raw at 0xC00 */
    pad(f, 0xC00);
    for (int i = 0; i < 0x600; i++) fputc(0xDD, f);

    /* Minimal code somewhere in .text (EP still unmapped) */
    unsigned char code[1] = {0xC3}; /* ret */
    long entry_raw = 0x200 + (0x1100 - 0x1000);
    fseek(f, entry_raw, SEEK_SET);
    w(f, code, sizeof(code));

    fclose(f);
    return 0;
}
