#include <windows.h>

char* dummy = "overlay fixture";

int main() {
    volatile char* sink = dummy;
    return 0;
}
