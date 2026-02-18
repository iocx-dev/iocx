#include <windows.h>

int main() {
    return 0;
}


/*
 Compile the resource file into a .res:
 x86_64-w64-mingw32-windres ioc_resources.rc -O coff -o ioc_resources.res

 Compile and link it with the resource:
 x86_64-w64-mingw32-gcc -o pe_with_rsrc_iocs.exe main.c ioc_resources.res

*/
