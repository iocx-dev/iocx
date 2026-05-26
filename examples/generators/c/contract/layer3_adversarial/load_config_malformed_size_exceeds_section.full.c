#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc;
    uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc;
    uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip;
    uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4];
    uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; int32_t e_lfanew;
} DOS;

typedef struct { uint32_t Signature; } PE_SIG;

typedef struct {
    uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader; uint16_t Characteristics;
} FILE_HDR;

typedef struct { uint32_t VirtualAddress; uint32_t Size; } DIR;

typedef struct {
    uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase;
    uint32_t SectionAlignment; uint32_t FileAlignment;
    uint16_t MajorOS; uint16_t MinorOS; uint16_t MajorImg; uint16_t MinorImg;
    uint16_t MajorSub; uint16_t MinorSub; uint32_t Win32Ver;
    uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum;
    uint16_t Subsystem; uint16_t DllChars;
    uint64_t StackRes; uint64_t StackCom; uint64_t HeapRes; uint64_t HeapCom;
    uint32_t LoaderFlags; uint32_t NumDirs; DIR DataDir[16];
} OPT64;

typedef struct {
    uint8_t Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress;
    uint32_t SizeOfRawData; uint32_t PointerToRawData;
    uint32_t PointerToRelocations; uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations; uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECT;

typedef struct {
    uint32_t Size; uint32_t TimeDateStamp;
    uint16_t MajorVersion; uint16_t MinorVersion;
    uint32_t GlobalFlagsClear; uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint64_t DeCommitFreeBlockThreshold;
    uint64_t DeCommitTotalFreeThreshold;
    uint64_t LockPrefixTable;
    uint64_t MaximumAllocationSize;
    uint64_t VirtualMemoryThreshold;
    uint64_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion;
    uint16_t DependentLoadFlags;
    uint64_t EditList;
    uint64_t SecurityCookie;
    uint64_t SEHandlerTable;
    uint64_t SEHandlerCount;
    uint64_t GuardCFCheckFunctionPointer;
    uint64_t GuardCFDispatchFunctionPointer;
    uint64_t GuardCFFunctionTable;
    uint64_t GuardCFFunctionCount;
    uint32_t GuardFlags;
} LOAD_CONFIG64;

#pragma pack(pop)

static void w(FILE *f, const void *b, size_t s) {
    if (fwrite(b, 1, s, f) != s) exit(1);
}

static void pad(FILE *f, long t) {
    while (ftell(f) < t) fputc(0, f);
}

int main(void) {
    FILE *f = fopen("load_config_malformed_size_exceeds_section.full.exe", "wb");
    if (!f) return 1;

    DOS dos = {0};
    dos.e_magic = 0x5A4D;
    dos.e_lfanew = 0x80;
    w(f, &dos, sizeof(dos));
    pad(f, dos.e_lfanew);

    PE_SIG sig = {0x00004550};
    w(f, &sig, sizeof(sig));

    FILE_HDR fh = {0};
    fh.Machine = 0x8664;
    fh.NumberOfSections = 2;
    fh.SizeOfOptionalHeader = sizeof(OPT64);
    fh.Characteristics = 0x22;
    w(f, &fh, sizeof(fh));

    OPT64 opt = {0};
    opt.Magic = 0x20B;
    opt.AddressOfEntryPoint = 0x1000;
    opt.BaseOfCode = 0x1000;
    opt.ImageBase = 0x140000000ULL;
    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;
    opt.SizeOfImage = 0x4000;
    opt.SizeOfHeaders = 0x400;
    opt.Subsystem = 3;
    opt.NumDirs = 16;

    opt.DataDir[10].VirtualAddress = 0x3000;
    opt.DataDir[10].Size = 0x2000; // extends far beyond .rdata

    w(f, &opt, sizeof(opt));

    SECT text = {0};
    memcpy(text.Name, ".text", 5);
    text.VirtualSize = 0x1000;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x400;
    text.Characteristics = 0x60000020;
    w(f, &text, sizeof(text));

    SECT rdata = {0};
    memcpy(rdata.Name, ".rdata", 6);
    rdata.VirtualSize = 0x200; // small section
    rdata.VirtualAddress = 0x3000;
    rdata.SizeOfRawData = 0x200;
    rdata.PointerToRawData = 0x600;
    rdata.Characteristics = 0x40000040;
    w(f, &rdata, sizeof(rdata));

    pad(f, 0x400);
    uint8_t code[16] = {0xC3};
    w(f, code, sizeof(code));

    pad(f, 0x600);
    LOAD_CONFIG64 lc = {0};
    lc.Size = sizeof(LOAD_CONFIG64);
    lc.SecurityCookie = 0x3500;
    w(f, &lc, sizeof(lc));

    fclose(f);
    return 0;
}
