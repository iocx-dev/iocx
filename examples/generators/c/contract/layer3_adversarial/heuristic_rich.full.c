#include <windows.h>

// --- Fake IOC-like strings in .data section (harmless) ----------------------
__attribute__((section(".data")))
const char fake_iocs[][64] = {
   "example-malware.com", // fake domain
   "192.0.2.123", // TEST-NET-1 IP (reserved, safe)
   "abcd1234ef567890abcd1234ef567890", // fake MD5-like string
   "FAKE-IOC-TEST-ONLY-1234567890", // generic test marker
   "hxxp://not-a-real-domain.test/payload"// safe obfuscated URL
};

// --- RWX section ------------------------------------------------------------
__attribute__((section(".rwx")))
volatile unsigned char rwx_buffer[2048];

// --- UPX0 section with noisy data ------------------------------------------
__attribute__((section("UPX0")))
const unsigned char upx0_data[4096] = {
   0x13,0x37,0x42,0x99,0xDE,0xAD,0xBE,0xEF,
   0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
   #define P(x) x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x
   P(0xAA), P(0x55), P(0xCC), P(0x33),
   P(0xF0), P(0x0F), P(0x5A), P(0xA5),
   #undef P
};

// --- Anti-debug + timing imports -------------------------------------------
__declspec(dllimport) BOOL WINAPI IsDebuggerPresent(void);
__declspec(dllimport) BOOL WINAPI CheckRemoteDebuggerPresent(HANDLE, PBOOL);
__declspec(dllimport) VOID WINAPI OutputDebugStringA(LPCSTR);

__declspec(dllimport) DWORD WINAPI GetTickCount(void);
__declspec(dllimport) ULONGLONG WINAPI GetTickCount64(void);
__declspec(dllimport) BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER*);

// --- Minimal program logic --------------------------------------------------
static void exercise_imports(void) {
   volatile BOOL dbg = IsDebuggerPresent();
   BOOL remote_dbg = FALSE;
   CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_dbg);
   OutputDebugStringA("heuristic_rich.full: debug string");

   volatile DWORD t = GetTickCount();
   volatile ULONGLONG t2 = GetTickCount64();
   LARGE_INTEGER li;
   QueryPerformanceCounter(&li);

   rwx_buffer[0] = (unsigned char)t;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int n) {
   exercise_imports();
   MessageBoxA(NULL, "heuristic_rich.full.exe", "Heuristic Test", MB_OK);
   return 0;
}
