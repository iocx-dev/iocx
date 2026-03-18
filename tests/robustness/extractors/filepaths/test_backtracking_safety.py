import pytest
from iocx.extractors.filepaths import extract

# ----------------------------------------------------------------------
# Catastrophic‑backtracking killer corpus
# ----------------------------------------------------------------------

def long(s, n=20000):
    return s * n

BACKTRACKING_CORPUS = [

    # --------------------------------------------------------------
    # 1. Repetition-based stress (long ambiguous runs)
    # --------------------------------------------------------------
    "C:" + long("A"),
    "./" + long("a"),
    "/tmp/" + long("x"),
    "\\\\server\\share\\" + long("x"),
    "$VAR/" + long("x"),

    # --------------------------------------------------------------
    # 2. Nested-quantifier traps (ambiguous separators)
    # --------------------------------------------------------------
    "C:\\" + long("\\") + "file.txt",
    "/" * 20000 + "etc/passwd",
    "./" + long("/") + "file",
    "\\\\server" + long("\\") + "share\\file",

    # --------------------------------------------------------------
    # 3. Alternation stress (suffixes that force many branches)
    # --------------------------------------------------------------
    "C:\\" + long("A") + long("?"),
    "xxx/usr/bin/" + long("?"),
    "~" + long("?") + "/file",
    "\\\\server\\share\\" + long("?") + "file",

    # --------------------------------------------------------------
    # 4. Unicode + control character ambiguity
    # --------------------------------------------------------------
    "/tmp/" + long("\u200b") + "file",
    "C:\\Users\\Public\\" + long("\u202E") + "evil.exe",
    "./" + long("\u0000") + "file",
    "\\\\server\\share\\" + long("\u200f") + "file",

    # --------------------------------------------------------------
    # 5. Deep directory nesting
    # --------------------------------------------------------------
    "/" + "/".join(["a"] * 5000),
    "C:\\" + "\\".join(["x"] * 5000),
    "\\\\server\\share\\" + "\\".join(["d"] * 5000),
    "./" + "/".join(["n"] * 5000),

    # --------------------------------------------------------------
    # 6. Hybrid separator storms
    # --------------------------------------------------------------
    "C:/" + long("\\/") + "file.txt",
    "/home/user" + long("\\/") + "file",
    "\\\\server\\share" + long("/\\") + "file",

    # --------------------------------------------------------------
    # 7. Boundary-ambiguity stress
    # --------------------------------------------------------------
    "C:\\Windows\\System32\\calc.exe" + long("x"),
    "/tmp/file.txt" + long("x"),
    "./run.sh" + long("x"),
    "~/bin/tool" + long("x"),

    # --------------------------------------------------------------
    # 8. Combined pathological payloads
    # --------------------------------------------------------------
    "C:\\" + long("A") + long("\\") + long("?") + "file.txt",
    "/" + long("a") + long("\u200b") + long("/") + "file",
    "\\\\server\\share\\" + long("x") + long("\u202E") + long("?") + "file",
    "~/" + long(".") + long("/") + long("?") + "file",
]

# ----------------------------------------------------------------------
# Test: extractor must never hang or crash
# ----------------------------------------------------------------------

@pytest.mark.parametrize("sample", BACKTRACKING_CORPUS)
@pytest.mark.robustness
@pytest.mark.timeout(0.5)   # fail fast if catastrophic backtracking occurs
def test_backtracking_safety(sample):
    out = extract(sample)
    assert isinstance(out, list)
