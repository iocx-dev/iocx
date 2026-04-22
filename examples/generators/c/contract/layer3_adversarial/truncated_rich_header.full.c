#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)
// same structs
#pragma pack(pop)

static void w(FILE *f,const void*b,size_t s){if(fwrite(b,1,s,f)!=s)exit(1);}
static void pad(FILE *f,long t){while(ftell(f)<t)fputc(0,f);}

int main(void){
    FILE *f=fopen("truncated_rich_header.full.exe","wb");
    if(!f)return 1;

    DOS dos={0};
    dos.e_magic=0x5A4D;
    dos.e_lfanew=0x80;
    w(f,&dos,sizeof(dos));

    long rich_start=ftell(f);
    for(int i=0;i<0x40;i++)fputc(0x90,f);

    const char sig[]="Rich";
    w(f,sig,sizeof(sig)-1);

    for(int i=0;i<16;i++)fputc(0xCC,f);

    // TRUNCATE: seek into middle of Rich blob
    fseek(f, rich_start + 0x10, SEEK_SET);

    pad(f,dos.e_lfanew);

    PE_SIG ps={0x00004550};
    w(f,&ps,sizeof(ps));

    FILE_HDR fh={0};
    fh.Machine=0x8664;
    fh.NumberOfSections=1;
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
    opt.SizeOfImage=0x3000;
    opt.SizeOfHeaders=0x200;
    opt.Subsystem=3;
    opt.NumDirs=16;
    w(f,&opt,sizeof(opt));

    SECT s={0};
    memcpy(s.Name,".text",5);
    s.VirtualSize=0x1000;
    s.VirtualAddress=0x1000;
    s.SizeOfRawData=0x200;
    s.PointerToRawData=0x200;
    s.Characteristics=0x60000020;
    w(f,&s,sizeof(s));

    pad(f,0x200);
    uint8_t code[16]={0xC3};
    w(f,code,sizeof(code));

    fclose(f);
    return 0;
}
