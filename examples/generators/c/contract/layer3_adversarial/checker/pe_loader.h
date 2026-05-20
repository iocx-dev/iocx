#pragma once
#include <windows.h>

typedef struct ParsedPe {
    uint8_t *buf;
    size_t size;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections;
    int num_sections;
} ParsedPe;

int load_pe(const char *path, ParsedPe *pe);
void free_pe(ParsedPe *pe);
int rva_to_raw(ParsedPe *pe, uint32_t rva, uint32_t *raw_out);
