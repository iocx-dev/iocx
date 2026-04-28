#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("base64_strings_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid base64 – but embedded inside tokens → should NOT be detected */
    w(f, "prefix-SGVsbG8sIFdvcmxkIQ==-suffix\n"); /* embedded, reject */
    w(f, "xxxxVXNlci1hZ2VudDogQmFzZTY0LXRlc3Q=yyyy\n"); /* embedded, reject */

    /* Valid base64 – standalone with boundaries → should be detected */
    w(f, "[QmFzZTY0IGlzIG5vdCBqdXN0IGZvciBiaW5hcnk=]\n");

    /* URL-safe base64 without padding → should be detected */
    w(f, "token:ZXhhbXBsZS11cmwtc2FmZS1iYXNlNjQ\n");

    /* Short base64-like:
       - QUJDREVGRw== decodes to ASCII "ABCDEFG" → should be detected
       - YWJjZA== decodes to "abcd" but too short → should NOT be detected
    */
    w(f, "short:QUJDREVGRw==\n");
    w(f, "tiny:YWJjZA==\n");

    /* Base64-like but decodes to binary → should NOT be detected */
    w(f, "bin1://///w8PDw8PDw8PDw8PDw8PDw8PDw8PDw8=\n");
    w(f, "bin2:AAAAAAAA8P///wD////A////AP///wD///8=\n");

    /* Base64-like but decodes to numeric-only → should NOT be detected */
    w(f, "noalpha:MTIzNDU2Nzg5MDA5ODc2NTQzMjEw\n");

    /* Base64-like inside a larger token → should NOT be detected */
    w(f, "wrapped_token=xxxSGVsbG8sIFdvcmxkIQ==yyy\n");

    /* Random noise with base64 alphabet → should NOT be detected */
    w(f, "noise:++++////++++////++++////\n");

    /* UTF‑16LE-like base64 → should NOT be detected (UTF‑16LE branch removed) */
    w(f, "dXRmMTYtTEU6AEgAZQBsAGwAbwAhAA==\n");

    fclose(f);
    return 0;
}
