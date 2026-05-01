#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("filepaths_strings_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid Windows absolute paths (full file references) */
    w(f, "C:\\Users\\Public\\document.txt\n");
    w(f, "D:\\Program Files\\App\\bin.exe\n");

    /* Common Windows system-utility paths (LOLBin-style executables) */
    w(f, "C:\\Windows\\System32\\cmd.exe\n");
    w(f, "C:\\Windows\\System32\\wscript.exe\n");
    w(f, "C:\\Windows\\System32\\mshta.exe\n");

    /* Valid UNC paths */
    w(f, "\\\\server01\\share\\folder\\file.log\n");
    w(f, "\\\\10.0.0.5\\data$\\dump.bin\n");

    /* Valid Unix absolute paths */
    w(f, "/usr/local/bin/script.sh\n");
    w(f, "/opt/app/config.yaml\n");

    /* Common Unix utility paths (LOLBin-style executables) */
    w(f, "/usr/bin/python3.11\n");
    w(f, "/usr/bin/openssl\n");

    /* Valid relative paths */
    w(f, ".\\temp\\run.cmd\n");
    w(f, "../logs/error.log\n");

    /* Valid tilde paths */
    w(f, "~/projects/code/main.py\n");
    w(f, "~user/docs/readme.md\n");

    /* Valid environment variable paths */
    w(f, "%APPDATA%\\MyApp\\config.json\n");
    w(f, "$HOME/.config/tool/settings.ini\n");

    /* Split paths (should match partial path fragments if syntactically correct) */
    w(f, "C:\\Users\\Pub\nlic\\broken.txt\n");
    w(f, "/usr/loc\nal/bin/bad.sh\n");

    /* Paths with spaces in final filename (should match up until the breaking whitespace) */
    w(f, "C:\\Temp\\my file.txt\n");
    w(f, "/var/log/my file.log\n");

    /* Log-like dotted keys (should NOT match) */
    w(f, "network.connection.error\n");
    w(f, "auth.failure.reason\n");

    /* URL-like strings (should be classified as URLs, not filepaths) */
    w(f, "http://example.com/path/file.txt\n");

    /* Garbage with embedded path-like fragments (should NOT match) */
    w(f, "xxx/usr/local/binxxx\n");

    /* Syntactically valid so should match */
    w(f, "C:\\Windows\\System32evil\n");

    fclose(f);
    return 0;
}
