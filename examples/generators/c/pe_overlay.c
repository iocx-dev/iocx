#include <windows.h>

char* dummy = "overlay fixture";

int main() {
    volatile char* sink = dummy;
    return 0;
}

// Append overlay IOCs:
// echo "http://overlay.net/c2" >> pe_overlay.exe
// echo "8.8.8.8" >> pe_overlay.exe
