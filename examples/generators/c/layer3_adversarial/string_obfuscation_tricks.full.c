#include <windows.h>
#include <string.h>

// Put obfuscated-ish data into a custom section ".obfs"
#ifdef _MSC_VER
# pragma section(".obfs", read, write)
__declspec(allocate(".obfs"))
char obfs_data[] =
#else
__attribute__((section(".obfs")))
char obfs_data[] =
#endif
{
    // Split URL parts (should NOT be reconstructed by IOCX)
    'h','t','t','p',':','/','/','e','x','a', // "http://exa"
    'm','p','l','e','.','c','o','m','/','p', // "mple.com/p"
    'a','t','h', // "ath"

    // Reversed domain (should NOT be treated as IOC)
    'm','o','c','.','e','l','p','m','a','x', // "moc.elpmaxe"

    // Interspersed nulls (wide-ish)
    'h','\0','t','\0','t','\0','p','\0',':','\0','/','\0','/','\0',
    'b','\0','a','\0','d','\0','.','\0','t','\0','e','\0','s','\0','t','\0',

    // Some random bytes to make it less trivial
    0x01,0xFF,0x23,0x7A,0x10,0x99
};

// Literal IOCs that *should* be extracted
static const char *literal_url = "http://literal-ioc.test/path";
static const char *literal_domain = "literal-domain.test";
static const char *literal_ip = "198.51.100.42";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    // Use the strings so the compiler doesn't drop them
    MessageBoxA(NULL, literal_url, "IOCX URL", MB_OK);
    MessageBoxA(NULL, literal_domain, "IOCX Domain", MB_OK);
    MessageBoxA(NULL, literal_ip, "IOCX IP", MB_OK);

    // Touch obfs_data so it stays
    if (obfs_data[0] == 'h') {
        OutputDebugStringA("obfs_data touched\n");
    }

    return 0;
}
