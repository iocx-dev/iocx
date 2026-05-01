#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("hashes_strings_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid MD5 */
    w(f, "d41d8cd98f00b204e9800998ecf8427e\n");

    /* Valid SHA1 */
    w(f, "da39a3ee5e6b4b0d3255bfef95601890afd80709\n");

    /* Valid SHA256 */
    w(f, "e3b0c44298fc1c149afbf4c8996fb924"
          "27ae41e4649b934ca495991b7852b855\n");

    /* Valid SHA512 */
    w(f, "cf83e1357eefb8bdf1542850d66d8007"
          "d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f"
          "63b931bd47417a81a538327af927da3e\n");

    /* Hex-like but too short (should NOT match) */
    w(f, "deadbeef\n");
    w(f, "cafebabe\n");

    /* Hex-like but too long / wrong length (should NOT match) */
    w(f, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"); /* 41 chars */
    w(f, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"); /* 44+ */

    /* Mixed-case valid hash (should match) */
    w(f, "D41D8CD98F00B204E9800998ECF8427E\n");

    /* Hash embedded in larger token (should NOT match) */
    w(f, "xxxd41d8cd98f00b204e9800998ecf8427eyyy\n");

    /* Hash split across lines
     * The first line contains 40 hex chars, which is valid SHA1.
     * Therefore the extractor WILL match the SHA1 substring
    */
    w(f, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4\n");
    w(f, "649b934ca495991b7852b855\n");

    /* GUID-like (should match last segment) */
    w(f, "550e8400-e29b-41d4-a716-446655440000\n");

    /* Random hex noise in a dump (should NOT match) */
    w(f, "00000000 41 41 41 41 42 42 42 42 |AAAA BBBB|\n");

    fclose(f);
    return 0;
}
