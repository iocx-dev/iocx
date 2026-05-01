#include <windows.h>
#include <string.h>

#ifdef _MSC_VER
# pragma section(".obfs", read, write)
__declspec(allocate(".obfs"))
char obfs_domain_data[] =
#else
__attribute__((section(".obfs")))
char obfs_domain_data[] =
#endif
{
    // Split domain (should NOT be reconstructed)
    'e','x','a','m','p','l','e','.','c','o',
    'm',

    // Reversed domain (should NOT be extracted)
    'm','o','c','.','e','l','p','m','a','x',

    // BAD_TLDS (should NOT be extracted)
    'c','o','n','f','i','g','.','j','s','o','n',
    's','c','r','i','p','t','.','j','s',
    'p','a','y','l','o','a','d','.','e','x','e',

    // Structured log lookalikes (should NOT be extracted)
    'n','e','t','w','o','r','k','.','c','o','n','n','e','c','t','i','o','n',
    'a','u','t','h','.','f','a','i','l','u','r','e',
    'l','o','g','.','c','o','r','r','u','p','t','i','o','n',

    // Deobfuscated-like domains (should only be extracted after deobfuscation)
    'e','v','i','l','[','.','d','e','v',
    'a','p','i','[','.','e','x','a','m','p','l','e','[','.','c','o','m',

    // Punycode reversed (should NOT be extracted)
    'i','a','p','.','n','-','-','x','n',

    // Random noise
    0xDE,0xAD,0xBE,0xEF
};

// Literal domains that SHOULD be extracted
static const char *literal_domain_1 = "example.com";
static const char *literal_domain_2 = "sub.domain.co.uk";
static const char *literal_domain_3 = "evil.dev";
static const char *literal_domain_4 = "xn--e1afmkfd.xn--p1ai";
static const char *literal_domain_5 = "test.online";
static const char *literal_domain_6 = "foo.xyz";
static const char *literal_domain_7 = "api.example.com";
static const char *literal_domain_8 = "sub.example.io";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    MessageBoxA(NULL, literal_domain_1, "DOMAIN1", MB_OK);
    MessageBoxA(NULL, literal_domain_2, "DOMAIN2", MB_OK);
    MessageBoxA(NULL, literal_domain_3, "DOMAIN3", MB_OK);
    MessageBoxA(NULL, literal_domain_4, "DOMAIN4", MB_OK);
    MessageBoxA(NULL, literal_domain_5, "DOMAIN5", MB_OK);
    MessageBoxA(NULL, literal_domain_6, "DOMAIN6", MB_OK);
    MessageBoxA(NULL, literal_domain_7, "DOMAIN7", MB_OK);
    MessageBoxA(NULL, literal_domain_8, "DOMAIN8", MB_OK);

    if (obfs_domain_data[0] == 'e') {
        OutputDebugStringA("obfs_domain_data touched\n");
    }

    return 0;
}
