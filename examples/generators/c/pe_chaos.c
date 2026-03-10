#include <windows.h>

// --- ASCII IOCs in .rdata/.data ---

static const char* WIN_PATHS[] = {
    "C:\\Windows\\System32\\cmd.exe",
    "D:\\Temp\\payload.bin",
    "E:/Users/Bob/AppData/Roaming/evil.dll",
    "F:\\Program Files\\SomeApp\\bin\\run.exe",
    "C:\\Users\\Alice\\Desktop\\notes.txt",
    "Z:\\Archive\\2024\\logs\\system.log",
};

static const char* UNC_PATHS[] = {
    "\\\\SERVER01\\share\\dropper.exe",
    "\\\\192.168.1.44\\c$\\Windows\\Temp\\run.ps1",
    "\\\\FILESRV\\public\\docs\\report.pdf",
    "\\\\NAS01\\data\\backups\\2024\\config.json",
};

static const char* UNIX_PATHS[] = {
    "/usr/bin/python3.11",
    "/etc/passwd",
    "/var/lib/docker/overlay2/abc123/config.v2.json",
    "/tmp/x1/x2/x3/x4/x5/script.sh",
    "/opt/tools/bin/runner",
    "/home/alice/.config/evil.sh",
};

static const char* REL_PATHS[] = {
    ".\\payload.exe",
    "..\\lib\\config.json",
    "./run.sh",
    "../bin/loader.so",
    ".\\scripts\\install.ps1",
};

static const char* ENV_PATHS[] = {
    "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
    "%TEMP%\\payload.exe",
    "%USERPROFILE%\\Downloads\\file.txt",
    "$HOME/.config/evil.sh",
    "$HOME/bin/run.sh",
    "$TMPDIR/cache/tmp123.bin",
};

// --- UTF-16LE IOCs in .rdata (wide strings) ---

static const wchar_t* W_WIN_PATH = L"C:\\Windows\\System32\\cmd.exe";
static const wchar_t* W_UNC_PATH = L"\\\\SERVER01\\share\\dropper.exe";
static const wchar_t* W_UNIX_PATH = L"/home/alice/.config/evil.sh";
static const wchar_t* W_ENV_PATH  = L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk";

// Prevent optimization
static void keep_str(const char* s) {
    volatile const char* sink = s;
    (void)sink;
}

static void keep_wstr(const wchar_t* s) {
    volatile const wchar_t* sink = s;
    (void)sink;
}

int main(void) {
    for (int i = 0; i < (int)(sizeof(WIN_PATHS)/sizeof(WIN_PATHS[0])); i++) keep_str(WIN_PATHS[i]);
    for (int i = 0; i < (int)(sizeof(UNC_PATHS)/sizeof(UNC_PATHS[0])); i++) keep_str(UNC_PATHS[i]);
    for (int i = 0; i < (int)(sizeof(UNIX_PATHS)/sizeof(UNIX_PATHS[0])); i++) keep_str(UNIX_PATHS[i]);
    for (int i = 0; i < (int)(sizeof(REL_PATHS)/sizeof(REL_PATHS[0])); i++) keep_str(REL_PATHS[i]);
    for (int i = 0; i < (int)(sizeof(ENV_PATHS)/sizeof(ENV_PATHS[0])); i++) keep_str(ENV_PATHS[i]);

    keep_wstr(W_WIN_PATH);
    keep_wstr(W_UNC_PATH);
    keep_wstr(W_UNIX_PATH);
    keep_wstr(W_ENV_PATH);

    // Call a few imports so they appear in the import table
    Sleep(10);
    GetModuleHandleA("kernel32.dll");
    CreateFileA("C:\\Windows\\Temp\\payload.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    return 0;
}

int wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show) {
    return main();
}
