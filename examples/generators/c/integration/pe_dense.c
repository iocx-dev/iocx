// pe_dense.c
#include <windows.h>

// Declare custom sections for MSVC
#pragma section(".rdata", read)
#pragma section(".idata", read, write)
#pragma section(".tls", read, write)

// A block of IOC-like strings (~300 bytes)
#define IOC_BLOCK \
    "http://example.com/path\n" \
    "https://malicious.test/update\n" \
    "C:\\Windows\\System32\\cmd.exe\n" \
    "C:\\Users\\Public\\Downloads\\payload.exe\n" \
    "/tmp/runme.sh\n" \
    "1.2.3.4\n" \
    "10.0.0.5\n" \
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334\n" \
    "fe80::1ff:fe23:4567:890a\n" \
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7k3qk4x\n" \
    "1BoatSLRHtKNngkdXEeobR76b53LETtpyT\n" \
    "0x1234567890abcdef1234567890abcdef12345678\n"

// Repeat IOC_BLOCK until we fill ~512 KB (rest is zero-filled)
__declspec(allocate(".rdata"))
const char IOC_PAYLOAD[512 * 1024] =
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK
    IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK IOC_BLOCK;

// Large .data section (~1 MB: 256k * 4 bytes)
volatile int LARGE_DATA[256 * 1024] = { 1 };

// Malformed import table (won't be used as real imports, but present in .idata)
__declspec(allocate(".idata"))
void* BAD_IMPORT_TABLE[4] = { (void*)0xFFFFFFFF, 0, 0, 0 };

// TLS directory (valid but unusual)
__declspec(allocate(".tls"))
void* TLS_CALLBACKS[2] = { (void*)0x12345678, 0 };

int main(void) {
    return LARGE_DATA[0];
}
