#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4], e_oemid, e_oeminfo, e_res2[10];
    int32_t e_lfanew;
} DOS;

typedef struct { uint32_t Signature; } PE_SIG;

typedef struct {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
} FILE_HDR;

typedef struct { uint32_t VirtualAddress, Size; } DIR;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOS, MinorOS, MajorImg, MinorImg, MajorSub, MinorSub;
    uint32_t Win32Ver, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllChars;
    uint64_t StackRes, StackCom, HeapRes, HeapCom;
    uint32_t LoaderFlags, NumDirs;
    DIR DataDir[16];
} OPT64;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
} SECT;

#pragma pack(pop)

static void w(FILE *f,const void*b,size_t s){ if(fwrite(b,1,s,f)!=s) exit(1); }
static void pad(FILE *f,long t){ while(ftell(f)<t) fputc(0,f); }

int main(void){
    FILE *f=fopen("overlapping_sections.full.exe","wb");
    if(!f) return 1;

    DOS dos={0};
    dos.e_magic=0x5A4D;
    dos.e_lfanew=0x80;
    w(f,&dos,sizeof(dos));
    pad(f,dos.e_lfanew);

    PE_SIG sig={0x00004550};
    w(f,&sig,sizeof(sig));

    FILE_HDR fh={0};
    fh.Machine=0x8664;
    fh.NumberOfSections=2; /* .text + .data overlapping */
    fh.SizeOfOptionalHeader=sizeof(OPT64);
    fh.Characteristics=0x2;
    w(f,&fh,sizeof(fh));

    OPT64 opt={0};
    opt.Magic=0x20B;
    opt.AddressOfEntryPoint=0x1000;
    opt.BaseOfCode=0x1000;
    opt.ImageBase=0x140000000ULL;
    opt.SectionAlignment=0x1000;
    opt.FileAlignment=0x200;
    opt.SizeOfImage=0x3000; /* too small for overlapping sections */
    opt.SizeOfHeaders=0x200;
    opt.Subsystem=3;
    opt.NumDirs=16;
    w(f,&opt,sizeof(opt));

    /* SECTION 1: .text */
    SECT text={0};
    memcpy(text.Name,".text",5);
    text.VirtualSize=0x2000; /* 8 KB */
    text.VirtualAddress=0x1000;
    text.SizeOfRawData=0x2000;
    text.PointerToRawData=0x200;
    text.Characteristics=0x60000020;
    w(f,&text,sizeof(text));

    /* SECTION 2: .data overlapping .text */
    SECT data={0};
    memcpy(data.Name,".data",5);
    data.VirtualSize=0x2000;
    data.VirtualAddress=0x1800; /* overlaps .text virtual range */
    data.SizeOfRawData=0x3000; /* raw size > virtual size */
    data.PointerToRawData=0x1000; /* overlaps .text raw range */
    data.Characteristics=0xC0000040;
    w(f,&data,sizeof(data));

    pad(f,0x200);
    uint8_t code[16]={0xC3};
    w(f,code,sizeof(code));

    fclose(f);
    return 0;
}
