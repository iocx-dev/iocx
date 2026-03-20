import pytest
from iocx.detectors.extractors.filepaths import extract
from iocx.models import Detection

# ---------------------------------------------------------
# Chaos corpus: attacker‑style malformed or obfuscated paths
# ---------------------------------------------------------
CHAOS_CORPUS = [
    # ---------------------------------------------------------
    # Windows absolute paths — malformed, obfuscated, tricky
    # ---------------------------------------------------------
    r"C:\Temp\A1B2.exe???",
    r"xxxC:\Windows\System32\cmd.exeYYY",
    r"C:\Path\With\..\Weird\..\cmd.exe",
    r"C:\Users\Public\☠️\evil.dll",
    r"C:\PROGRA~1\Malwar~1\evil.exe::::",
    r"C:\path\CON\aux.txt",
    r"C:\\\\double\\\\slashes\\\\file.txt",
    r"C:\Windows\System32\drivers\etc\hosts#####",
    r"C:\Windows\System32\calc.exe suffix",     # boundary test
    r"C:\Windows\System32\calc.exesuffix",

    # ---------------------------------------------------------
    # UNC paths — malformed, greedy, admin shares, weird hosts
    # ---------------------------------------------------------
    r"\\SERVER\Share\folder\file.exe???",
    r"xxx\\192.168.1.50\C$\Temp\evil.dllxxx",
    r"\\LONG-SERVER_123\SHARE$\sub\dir\evil.bin",
    r"\\server\share suffix",                   # boundary test
    r"\\server\share_suffix",
    r"\\server\share\file.exe suffix",          # greedy test
    r"\\server\share\file.exesuffix",
    r"\\server only",                           # invalid
    r"\\server\ spaced\share",                  # invalid share

    # ---------------------------------------------------------
    # UNIX absolute paths — obfuscation, unicode, weird chars
    # ---------------------------------------------------------
    "/usr/local/bin/run???",
    "xxx/etc/passwdyyy",
    "/var/log/.hidden/logfile::::",
    "/tmp/Ωmega/script.sh###",
    "/home/user/space in name/file.txt",
    "/./weird/./path/./file",
    "/tmp/file\nname",                          # newline inside
    "/tmp/file\tname",                          # tab inside
    "/tmp/file name",                           # space in filename (invalid)
    "/tmp/file.namesuffix",                     # boundary test

    # ---------------------------------------------------------
    # Relative paths — attacker‑style
    # ---------------------------------------------------------
    "./65LQ???",
    "../tmp/run###",
    "../../etc/passwd",
    "./.hidden::::",
    "./0xDEADBEEFxxx",
    "../O0O0O0",
    "./file.txt suffix",                        # boundary test
    "./file.txtsuffix",

    # ---------------------------------------------------------
    # Tilde paths — weird usernames, unicode, obfuscation
    # ---------------------------------------------------------
    "~/tmp/run???",
    "~root/.ssh/id_rsa::::",
    "~Admin/Downloads/file.txtxxx",
    "~user123/Ωmega/script.sh",
    "~/.config/evil###",
    "~/.bashrc suffix",                         # boundary test
    "~/.bashrcsuffix",

    # ---------------------------------------------------------
    # Environment variable paths — mixed OS, malformed
    # ---------------------------------------------------------
    r"%APPDATA%\Microsoft\evil.lnk???",
    r"%TEMP%\..\Local\Temp\payload.exe",
    "$HOME/.cache/tmp/run###",
    "$USER/bin/evil???",
    "$TMPDIR/../tmp/obf",
    "%NOTCLOSED\path.exe",                      # malformed
    "$not valid/path",                          # valid var, valid path
    "$VAR/file suffix",                         # boundary test
    "$VAR/filesuffix",

    # ---------------------------------------------------------
    # Mixed separators and hybrid paths
    # ---------------------------------------------------------
    r"C:/Windows\System32/mixed\slashes.exe",
    "/home/user\\weird/mix/of\\separators",
    r"\\server/share/dir\subdir/file???",
    r"C:\path/with\mixed/slashes.txtsuffix",

    # ---------------------------------------------------------
    # Unicode, invisible, homoglyphs, control chars
    # ---------------------------------------------------------
    "/tmp/файл.sh",
    r"C:\Users\Public\☠️\evil.exe",
    "/home/user/zero‑width\u200bspace/file",
    "/tmp/\u202Eevil.txt",                      # RTL override
    "/tmp/file\u0000name",                      # null byte
    "/tmp/file\u200fname",                      # narrow no‑break space

    # ---------------------------------------------------------
    # Reserved or tricky names
    # ---------------------------------------------------------
    "/dev/null###",
    "/dev/tcp/127.0.0.1/8080???",
    r"C:\path\PRN\file.txt",
    r"C:\Windows\System32\drivers\etc\hosts::::",

    # ---------------------------------------------------------
    # Deep or long paths
    # ---------------------------------------------------------
    "/a/b/c/d/e/f/g/h/i/j/k/file",
    r"C:\very\deep\path\one\two\three\four\file.txt",

    # ---------------------------------------------------------
    # NEW: Edge cases that previously caused regressions
    # ---------------------------------------------------------
    r"\\server\share\file.exe suffix",          # UNC greediness
    r"\\server\share\file.exesuffix",           # UNC boundary
    "$VAR/path suffix",                         # ENV boundary
    "$VAR/pathsuffix",                          # ENV boundary fail
    "~/.bashrc suffix",                         # tilde boundary
    "~/.bashrcsuffix",                          # tilde boundary fail
]

@pytest.mark.parametrize("sample", CHAOS_CORPUS)
@pytest.mark.robustness
def test_chaos_corpus(sample):
    out = extract(sample)

    # Must always return a list of Detection objects
    assert isinstance(out, list)
    for d in out:
        assert hasattr(d, "value")
        assert hasattr(d, "start")
        assert hasattr(d, "end")
        assert hasattr(d, "category")
