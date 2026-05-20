#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "pe_loader.h"

int load_pe(const char *path, ParsedPe *pe)
{
    memset(pe, 0, sizeof(*pe));

    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = malloc(size);
    if (!buf) { fclose(fp); return 0; }
    fread(buf, 1, size, fp);
    fclose(fp);

    pe->buf = buf;
    pe->size = size;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    pe->nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    if (pe->nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    pe->sections = IMAGE_FIRST_SECTION(pe->nt);
    pe->num_sections = pe->nt->FileHeader.NumberOfSections;

    return 1;
}

void free_pe(ParsedPe *pe)
{
    if (pe->buf)
        free(pe->buf);
    memset(pe, 0, sizeof(*pe));
}

int rva_to_raw(ParsedPe *pe, uint32_t rva, uint32_t *raw_out)
{
    for (int i = 0; i < pe->num_sections; ++i) {
        IMAGE_SECTION_HEADER *s = &pe->sections[i];
        uint32_t va = s->VirtualAddress;
        uint32_t vs = s->Misc.VirtualSize;

        if (rva >= va && rva < va + vs) {
            uint32_t delta = rva - va;
            *raw_out = s->PointerToRawData + delta;
            return 1;
        }
    }
    return 0;
}
