#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

static void write_long_url(FILE *f) {
    /* Build a very long but syntactically valid URL */
    fputs("http://example.com/", f);
    for (int i = 0; i < 2500; i++) {
        fputc('a', f);
    }
    fputs("?q=1\n", f);
}

int main(void) {
    FILE *f = fopen("malformed_urls_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Broken schemes (should NOT be treated as URLs) */
    w(f, "htp://broken-scheme.example.com\n");
    w(f, "hxxp://obfuscated.example.com\n");

    /* Valid URLs (should be detected) */
    w(f, "http://valid.example.com/path?param=value\n");
    w(f, "https://sub.domain.example.org/index.html\n");

    /* Nested / repeated encodings */
    w(f, "http://example.com/%2525252e%252e/%252e/\n");
    w(f, "https://example.com/path/%2e%2e/%2e%2e/\n");

    /* Truncated / partial URLs (should be ignored) */
    w(f, "http://example.\n");
    w(f, "https://\n");

    /* Extremely long URL */
    write_long_url(f);

    fclose(f);
    return 0;
}
