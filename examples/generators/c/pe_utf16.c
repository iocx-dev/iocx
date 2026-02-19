#include <windows.h>

// UTF‑16 IOCs embedded as wide strings
wchar_t* ioc_1 = L"http://evil.com/door";
wchar_t* ioc_2 = L"172.16.0.77";

int main() {
    volatile wchar_t* sink;
    sink = ioc_1;
    sink = ioc_2;
    return 0;
}
