#include <windows.h>
#include <string.h>

#ifdef _MSC_VER
# pragma section(".obfs", read, write)
__declspec(allocate(".obfs"))
char obfs_url_data[] =
#else
__attribute__((section(".obfs")))
char obfs_url_data[] =
#endif
{
    // Split URL parts (should NOT be reconstructed)
    'h','t','t','p',':','/','/','e','x','a',
    'm','p','l','e','.','c','o','m','/','p',
    'a','t','h',

    // Broken IPv6 URL (should NOT be extracted)
    'h','t','t','p',':','/','/','[',':',':',':',':',']','/','b','a','d',

    // Malformed IPv6 host (should NOT be extracted)
    'h','t','t','p',':','/','/','[','2','0','0','1',':','d','b','8',':',':','g',']',

    // Reversed URL (should NOT be extracted)
    'm','o','c','.','l','i','v','e','/','/',':','p','t','t','h',

    // Interspersed nulls (wide-ish, should NOT be extracted)
    'h','\0','t','\0','t','\0','p','\0',':','\0','/','\0','/','\0',
    'b','\0','a','\0','d','\0','.','\0','t','\0','e','\0','s','\0','t','\0',

    // Deobfuscation-like (should only be extracted after deobfuscation, if enabled)
    'h','x','x','p',':','/','/','e','v','i','l','[','.','d','e','v','/','p','a','t','h',

    // URL with domain in query (tests suppression)
    'h','t','t','p',':','/','/','g','a','t','e','w','a','y','.','l','o','c','a','l',
    '/','r','e','d','i','r','e','c','t','?','t','a','r','g','e','t','=','e','x','a','m','p','l','e','.','c','o','m',

    // URL with IP in host (tests suppression)
    'h','t','t','p',':','/','/','1','5','6','.','6','5','.','4','2','.','8','/','a','c','c','e','s','s','.','p','h','p',

    // Random noise
    0x01,0xFF,0x23,0x7A,0x10,0x99
};

// Literal URLs that SHOULD be extracted
static const char *literal_url_1 = "http://example.com";
static const char *literal_url_2 = "https://sub.example.co.uk/path?x=1#frag";
static const char *literal_url_3 = "sftp://files.example.com/home";
static const char *literal_url_4 = "https://[2001:db8::1]/c2";
static const char *literal_url_5 = "ftps://secure.example.org/download";
static const char *literal_url_6 = "http://gateway.local/redirect?target=example.com";
static const char *literal_url_7 = "https://156.65.42.8/access.php";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    MessageBoxA(NULL, literal_url_1, "URL1", MB_OK);
    MessageBoxA(NULL, literal_url_2, "URL2", MB_OK);
    MessageBoxA(NULL, literal_url_3, "URL3", MB_OK);
    MessageBoxA(NULL, literal_url_4, "URL4", MB_OK);
    MessageBoxA(NULL, literal_url_5, "URL5", MB_OK);
    MessageBoxA(NULL, literal_url_6, "URL6", MB_OK);
    MessageBoxA(NULL, literal_url_7, "URL7", MB_OK);

    if (obfs_url_data[0] == 'h') {
        OutputDebugStringA("obfs_url_data touched\n");
    }

    return 0;
}
