#include <windows.h>
#include <string.h>

#ifdef _MSC_VER
# pragma section(".obfs", read, write)
__declspec(allocate(".obfs"))
char obfs_franken_data[] =
#else
__attribute__((section(".obfs")))
char obfs_franken_data[] =
#endif
{
    // --- URL-like adversarial content ---

    // Split URL
    'h','t','t','p',':','/','/','e','x','a','m','p','l','e','.','c','o','m','/','p','a','t','h',

    // Malformed IPv6 URL
    'h','t','t','p',':','/','/','[','2','0','0','1',':','d','b','8',':',':','g',']',':','4','4','3','/','i','n','v','a','l','i','d',

    // Broken bracketed host
    'h','t','t','p',':','/','/','[',':',':',':',':',']','/','b','a','d',

    // Reversed URL
    'm','o','c','.','l','i','v','e','/','/',':','p','t','t','h',

    // hxxp + [.] style
    'h','x','x','p',':','/','/','e','v','i','l','[','.','d','e','v','/','p','a','t','h',

    // URL with domain in query
    'h','t','t','p',':','/','/','g','a','t','e','w','a','y','.','l','o','c','a','l',
    '/','r','e','d','i','r','e','c','t','?','t','a','r','g','e','t','=','e','x','a','m','p','l','e','.','c','o','m',

    // URL with IP in host
    'h','t','t','p',':','/','/','1','5','6','.','6','5','.','4','2','.','8','/','a','c','c','e','s','s','.','p','h','p',

    // --- Domain-like adversarial content ---

    // Split domain
    'e','x','a','m','p','l','e','.','c','o','m',

    // Reversed domain
    'm','o','c','.','e','l','p','m','a','x',

    // BAD_TLDS
    'c','o','n','f','i','g','.','j','s','o','n',
    'p','a','y','l','o','a','d','.','e','x','e',

    // Structured log lookalikes
    'n','e','t','w','o','r','k','.','c','o','n','n','e','c','t','i','o','n',
    'a','u','t','h','.','f','a','i','l','u','r','e',

    // Deobfuscation-style domains
    'e','v','i','l','[','.','d','e','v',
    'a','p','i','[','.','e','x','a','m','p','l','e','[','.','c','o','m',

    // --- IP-like adversarial content ---

    // Split IPv4
    '1','9','2','.','1','6','8','.', '1','\n','1','0',

    // Split IPv6
    '2','0','0','1',':','d','b','8',':',':','\n','1',

    // Concatenated IPv4
    '1','9','2','.','1','6','8','.','1','.','1','1','0','.','0','.','0','.','1',

    // Malformed IPv6
    '2','0','0','1',':','d','b','8',':',':','g',

    // Mixed IPv6 + domain
    '2','0','0','1',':','d','b','8',':',':','1','e','v','i','l','.','d','e','v',

    // Bracketed IPv6
    '[','2','0','0','1',':','d','b','8',':',':','1',']',

    // Random noise
    0x01,0x02,0x03,0xAA,0xBB,0xCC,0xDD
};

// Literal URLs that SHOULD be extracted
static const char *f_url_1 = "http://example.com";
static const char *f_url_2 = "https://sub.example.co.uk/path?x=1#frag";
static const char *f_url_3 = "sftp://files.example.com/home";
static const char *f_url_4 = "https://[2001:db8::1]/c2";
static const char *f_url_5 = "ftps://secure.example.org/download";
static const char *f_url_6 = "http://gateway.local/redirect?target=example.com";
static const char *f_url_7 = "https://156.65.42.8/access.php";

// Literal domains that SHOULD be extracted
static const char *f_dom_1 = "example.com";
static const char *f_dom_2 = "sub.domain.co.uk";
static const char *f_dom_3 = "evil.dev";
static const char *f_dom_4 = "xn--e1afmkfd.xn--p1ai";
static const char *f_dom_5 = "test.online";
static const char *f_dom_6 = "foo.xyz";
static const char *f_dom_7 = "api.example.com";
static const char *f_dom_8 = "sub.example.io";

// Literal IPs that SHOULD be extracted
static const char *f_ip_1 = "1.2.3.4";
static const char *f_ip_2 = "10.0.0.1";
static const char *f_ip_3 = "192.168.1.10";
static const char *f_ip_4 = "8.8.8.8";
static const char *f_ip_5 = "10.0.0.0/8";
static const char *f_ip_6 = "192.168.0.0/16";
static const char *f_ip_7 = "2001:db8::/32";
static const char *f_ip_8 = "2001:db8::1";
static const char *f_ip_9 = "fe80::1";
static const char *f_ip_10 = "fe80::dead:beef";
static const char *f_ip_11 = "fe80::1%eth0";
static const char *f_ip_12 = "::2%eth1";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    // Touch URLs
    MessageBoxA(NULL, f_url_1, "F_URL1", MB_OK);
    MessageBoxA(NULL, f_url_2, "F_URL2", MB_OK);
    MessageBoxA(NULL, f_url_3, "F_URL3", MB_OK);
    MessageBoxA(NULL, f_url_4, "F_URL4", MB_OK);
    MessageBoxA(NULL, f_url_5, "F_URL5", MB_OK);
    MessageBoxA(NULL, f_url_6, "F_URL6", MB_OK);
    MessageBoxA(NULL, f_url_7, "F_URL7", MB_OK);

    // Touch domains
    MessageBoxA(NULL, f_dom_1, "F_DOM1", MB_OK);
    MessageBoxA(NULL, f_dom_2, "F_DOM2", MB_OK);
    MessageBoxA(NULL, f_dom_3, "F_DOM3", MB_OK);
    MessageBoxA(NULL, f_dom_4, "F_DOM4", MB_OK);
    MessageBoxA(NULL, f_dom_5, "F_DOM5", MB_OK);
    MessageBoxA(NULL, f_dom_6, "F_DOM6", MB_OK);
    MessageBoxA(NULL, f_dom_7, "F_DOM7", MB_OK);
    MessageBoxA(NULL, f_dom_8, "F_DOM8", MB_OK);

    // Touch IPs
    MessageBoxA(NULL, f_ip_1, "F_IP1", MB_OK);
    MessageBoxA(NULL, f_ip_2, "F_IP2", MB_OK);
    MessageBoxA(NULL, f_ip_3, "F_IP3", MB_OK);
    MessageBoxA(NULL, f_ip_4, "F_IP4", MB_OK);
    MessageBoxA(NULL, f_ip_5, "F_IP5", MB_OK);
    MessageBoxA(NULL, f_ip_6, "F_IP6", MB_OK);
    MessageBoxA(NULL, f_ip_7, "F_IP7", MB_OK);
    MessageBoxA(NULL, f_ip_8, "F_IP8", MB_OK);
    MessageBoxA(NULL, f_ip_9, "F_IP9", MB_OK);
    MessageBoxA(NULL, f_ip_10, "F_IP10", MB_OK);
    MessageBoxA(NULL, f_ip_11, "F_IP11", MB_OK);
    MessageBoxA(NULL, f_ip_12, "F_IP12", MB_OK);

    if (obfs_franken_data[0] == 'h') {
        OutputDebugStringA("obfs_franken_data touched\n");
    }

    return 0;
}
