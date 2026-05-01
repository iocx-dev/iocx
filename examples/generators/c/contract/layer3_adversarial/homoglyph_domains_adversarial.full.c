#include <stdio.h>
#include <string.h>

/* Some UTF-8 homoglyphs embedded as literals. */

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("homoglyph_domains_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid ASCII domains (should be detected) */
    w(f, "normal domains: paypal.com google.com microsoft.com example.org\n");

    /* Cyrillic 'p' (U+0440) and 'a' (U+0430) in place of Latin */
    w(f, "homoglyph: раураl.com\n"); /* looks like paypal.com */
    w(f, "homoglyph: gоogle.com\n"); /* Greek omicron in place of 'o' */

    /* Mixed-script domains */
    w(f, "mixed-script: microsоft.cоm\n"); /* Cyrillic 'о' */

    /* Punycode-like but invalid / deceptive */
    w(f, "xn--paypaI-l2c.com\n"); /* capital I instead of l */
    w(f, "xn--g00gle-9za.com\n");

    /* Random Unicode noise around domain-like text */
    w(f, "noise: ✪раураl.com✪ and ❖gοοgle.com❖\n");

    fclose(f);
    return 0;
}
