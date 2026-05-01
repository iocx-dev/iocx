#include <windows.h>
#include <string.h>

#ifdef _MSC_VER
# pragma section(".obfs", read, write)
__declspec(allocate(".obfs"))
char obfs_ip_data[] =
#else
__attribute__((section(".obfs")))
char obfs_ip_data[] =
#endif
{
    // Split IPv4 (should NOT be reconstructed)
    '1','9','2','.','1','6','8','.',
    '1','\n','1','0',

    // Split IPv6 (should NOT be reconstructed)
    '2','0','0','1',':','d','b','8',':',':','\n','1',

    // Concatenated IPv4 (salvage behaviour)
    '1','9','2','.','1','6','8','.','1','.','1','1','0','.','0','.','0','.','1',

    // Malformed IPv6 (should NOT be extracted)
    '2','0','0','1',':','d','b','8',':',':','g',

    // Mixed garbage with IP-like content
    '2','0','0','1',':','d','b','8',':',':','1','e','v','i','l','.','d','e','v',

    // Bracketed IPv6 without URL context (should still be seen as IP)
    '[','2','0','0','1',':','d','b','8',':',':','1',']',

    // Random noise
    0xAA,0xBB,0xCC,0xDD
};

// Literal IPs that SHOULD be extracted
static const char *literal_ip_1 = "1.2.3.4";
static const char *literal_ip_2 = "10.0.0.1";
static const char *literal_ip_3 = "192.168.1.10";
static const char *literal_ip_4 = "8.8.8.8";
static const char *literal_ip_5 = "10.0.0.0/8";
static const char *literal_ip_6 = "192.168.0.0/16";
static const char *literal_ip_7 = "2001:db8::/32";
static const char *literal_ip_8 = "2001:db8::1";
static const char *literal_ip_9 = "fe80::1";
static const char *literal_ip_10 = "fe80::dead:beef";
static const char *literal_ip_11 = "fe80::1%eth0";
static const char *literal_ip_12 = "::2%eth1";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    MessageBoxA(NULL, literal_ip_1, "IP1", MB_OK);
    MessageBoxA(NULL, literal_ip_2, "IP2", MB_OK);
    MessageBoxA(NULL, literal_ip_3, "IP3", MB_OK);
    MessageBoxA(NULL, literal_ip_4, "IP4", MB_OK);
    MessageBoxA(NULL, literal_ip_5, "IP5", MB_OK);
    MessageBoxA(NULL, literal_ip_6, "IP6", MB_OK);
    MessageBoxA(NULL, literal_ip_7, "IP7", MB_OK);
    MessageBoxA(NULL, literal_ip_8, "IP8", MB_OK);
    MessageBoxA(NULL, literal_ip_9, "IP9", MB_OK);
    MessageBoxA(NULL, literal_ip_10, "IP10", MB_OK);
    MessageBoxA(NULL, literal_ip_11, "IP11", MB_OK);
    MessageBoxA(NULL, literal_ip_12, "IP12", MB_OK);

    if (obfs_ip_data[0] == '1') {
        OutputDebugStringA("obfs_ip_data touched\n");
    }

    return 0;
}
