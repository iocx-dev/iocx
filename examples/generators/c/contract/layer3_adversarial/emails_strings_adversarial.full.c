#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("emails_strings_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid emails */
    w(f, "contact@example.com\n");
    w(f, "first.last@sub.domain.co.uk\n");
    w(f, "user+tag@my-server.example\n");

    /* Valid email inside URL (should still match) */
    w(f, "mailto:admin@example.org\n");

    /* Emails surrounded by underscores
     * With the classic word-boundary regex, this will NOT match
     * because "_" is not a word character and breaks \b boundaries.

     */
    w(f, "xxx_support@company.com_yyy\n");

    /*
     * Emails inside larger tokens.
     * With the permissive 90% regex, these WILL match.
     * The extractor will pull out the email-like substring.
     */
    w(f, "token=abc123user@example.comxyz\n");

    /* Missing TLD (should NOT match) */
    w(f, "broken@localhost\n");
    w(f, "user@domain\n");

    /* TLD too short (should NOT match) */
    w(f, "bad@domain.c\n");

    /* Numeric-only TLD (should NOT match) */
    w(f, "weird@domain.123\n");

    /* Split emails (should NOT match) */
    w(f, "split@exa\nmple.com\n");

    /* Log-like dotted keys (should NOT match) */
    w(f, "auth.failure.reason\n");
    w(f, "network.connection.error\n");

    /* Garbage with @ signs (should NOT match) */
    w(f, "@@@@notanemail@@@@\n");
    w(f, "user@@example.com\n");

    fclose(f);
    return 0;
}

