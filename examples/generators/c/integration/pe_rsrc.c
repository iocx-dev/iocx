#include <windows.h>

int main() {
    // IOCs embedded in the .rsrc section via STRINGTABLE
    // Load strings from resource section to ensure they are included
    wchar_t buffer[256];

    LoadStringW(GetModuleHandleW(NULL), 1, buffer, 256);
    LoadStringW(GetModuleHandleW(NULL), 2, buffer, 256);

    return 0;
}
