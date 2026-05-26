#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)
typedef struct { uint16_t e_magic; uint16_t pad[29]; int32_t e_lfanew; } DOS;
typedef struct { uint32_t Signature; } PE_SIG;
typedef struct {
    uint16_t Machine, NumberOfSections; uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
} FILE_HDR;
typedef struct { uint32_t VirtualAddress, Size; } DIR;
typedef struct {
    uint16_t Magic; uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode; uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOS, MinorOS, MajorImg, MinorImg;
    uint16_t MajorSub, MinorSub; uint32_t Win32Ver;
    uint32_t SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllChars;
    uint64_t StackRes, StackCom, HeapRes, HeapCom;
    uint32_t LoaderFlags, NumDirs; DIR DataDir[16];
} OPT64;
typedef struct {
    uint8_t Name[8]; uint32_t VirtualSize, VirtualAddress;
    uint32_t SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
} SECT;
typedef struct {
    uint32_t Size, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t GlobalFlagsClear, GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint64_t DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
    uint64_t LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold;
    uint64_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion, DependentLoadFlags;
    uint64_t EditList, SecurityCookie, SEHandlerTable, SEHandlerCount;
    uint64_t GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer;
    uint64_t GuardCFFunctionTable, GuardCFFunctionCount;
    uint32_t GuardFlags;
} LOAD_CONFIG64;
#pragma pack(pop)

static void w(FILE *f, const void *b, size_t s){ if(fwrite(b,1,s,f)!=s)exit(1);}
static void pad(FILE *f, long t){ while(ftell(f)<t) fputc(0,f); }

int main(void){
    FILE *f=fopen("load_config_zero_size_but_fields_present.full.exe","wb");
    if(!f)return 1;

    DOS dos={0}; dos.e_magic=0x5A4D; dos.e_lfanew=0x80; w(f,&dos,sizeof(dos)); pad(f,dos.e_lfanew);
    PE_SIG sig={0x00004550}; w(f,&sig,sizeof(sig));

    FILE_HDR fh={0}; fh.Machine=0x8664; fh.NumberOfSections=2; fh.SizeOfOptionalHeader=sizeof(OPT64); fh.Characteristics=0x22;
    w(f,&fh,sizeof(fh));

    OPT64 opt={0};
    opt.Magic=0x20B; opt.AddressOfEntryPoint=0x1000; opt.BaseOfCode=0x1000;
    opt.ImageBase=0x140000000ULL; opt.SectionAlignment=0x1000; opt.FileAlignment=0x200;
    opt.SizeOfImage=0x4000; opt.SizeOfHeaders=0x400; opt.Subsystem=3; opt.NumDirs=16;
    opt.DataDir[10].VirtualAddress=0x3000; // valid RVA in .rdata
    opt.DataDir[10].Size=0; // zero-length directory
    w(f,&opt,sizeof(opt));

    SECT text={0}; memcpy(text.Name,".text",5);
    text.VirtualSize=0x1000; text.VirtualAddress=0x1000;
    text.SizeOfRawData=0x200; text.PointerToRawData=0x400;
    text.Characteristics=0x60000020; w(f,&text,sizeof(text));

    SECT rdata={0}; memcpy(rdata.Name,".rdata",6);
    rdata.VirtualSize=0x1000; rdata.VirtualAddress=0x3000;
    rdata.SizeOfRawData=0x200; rdata.PointerToRawData=0x600;
    rdata.Characteristics=0x40000040; w(f,&rdata,sizeof(rdata));

    pad(f,0x400); uint8_t code[16]={0xC3}; w(f,code,sizeof(code));

    pad(f,0x600);
    LOAD_CONFIG64 lc={0};
    lc.Size=sizeof(LOAD_CONFIG64);
    lc.SecurityCookie=0x3500; // non-zero field
    lc.SEHandlerCount=4; // more non-zero fields
    lc.GuardCFCheckFunctionPointer=0x3600;
    w(f,&lc,sizeof(lc));

    fclose(f); return 0;
}
