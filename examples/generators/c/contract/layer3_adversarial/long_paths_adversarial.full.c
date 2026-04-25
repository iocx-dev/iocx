#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

static void write_very_long_path(FILE *f) {
    fputs("C:\\very", f);
    for (int i = 0; i < 50; i++) {
        fputs("\\nested", f);
    }
    fputs("\\file.txt\n", f);
}

int main(void) {
    FILE *f = fopen("long_paths_adversarial.full.bin", "wb");
    if (!f) return 0;

    /* Valid Windows paths (should be detected) */
    w(f, "C:\\Windows\\System32\\cmd.exe\n");
    w(f, "C:\\Program Files\\TestApp\\app.exe\n");

    /* Deeply nested directory structure */
    w(f, "C:\\a\\b\\c\\d\\e\\f\\g\\h\\i\\j\\k\\l\\m\\n\\o\\p\\q\\r\\s\\t\\u\\v\\w\\x\\y\\z\\file.txt\n");

    /* Path exceeding MAX_PATH */
    write_very_long_path(f);

    /* Malformed UNC prefixes (should NOT be treated as valid paths) */
    w(f, "\\\\?\\UNC\\\\server\\share\\folder\\file.txt\n");
    w(f, "\\\\\\server\\share\\badprefix\\file.txt\n");

    fclose(f);
    return 0;
}
