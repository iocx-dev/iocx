#include <windows.h>

// ASCII IOCs embedded as normal C strings in .data
char* ioc_1 = "http://example.com/c2";
char* ioc_2 = "192.168.44.10";
char* ioc_3 = "abcd1234deadbeef";

int main() {
    // Prevent compiler from optimizing strings away
    volatile char* sink;
    sink = ioc_1;
    sink = ioc_2;
    sink = ioc_3;
    return 0;
}
