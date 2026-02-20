import pytest

from iocx.extractors.filepaths import (
    WINDOWS_ABS,
    UNC_PATH,
    UNIX_ABS,
    RELATIVE_PATH,
    ENV_PATH,
    extract,
)

# -----------------------------
# WINDOWS ABSOLUTE PATHS
# -----------------------------

@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\cmd.exe",
    r"D:\Temp\run.exe",
    r"E:/Users/Bob/AppData/Roaming/evil.dll",
])
def test_windows_abs_matches(path):
    assert WINDOWS_ABS.search(path)


@pytest.mark.parametrize("text", [
    "C:WindowsSystem32",      # missing slashes
    "C:\\",                   # no filename
    "Z://///",                # nonsense
])
def test_windows_abs_negative(text):
    assert not WINDOWS_ABS.search(text)


# -----------------------------
# UNC PATHS
# -----------------------------

@pytest.mark.parametrize("path", [
    r"\\SERVER01\share\dropper.exe",
    r"\\192.168.1.44\c$\Windows\Temp\run.ps1",
])
def test_unc_matches(path):
    assert UNC_PATH.search(path)


@pytest.mark.parametrize("text", [
    r"\SERVER\share\file.txt",   # missing leading slashes
    r"\\server",                 # incomplete
])
def test_unc_negative(text):
    assert not UNC_PATH.search(text)


# -----------------------------
# UNIX ABSOLUTE PATHS
# -----------------------------

@pytest.mark.parametrize("path", [
    "/usr/bin/python",
    "/etc/passwd",
    "/var/lib/docker/overlay2/abc123/config.v2.json",
])
def test_unix_abs_matches(path):
    assert UNIX_ABS.search(path)


@pytest.mark.parametrize("text", [
    "usr/bin/python",   # missing leading slash
    "/justslash/",      # ends with slash only
])
def test_unix_abs_negative(text):
    assert not UNIX_ABS.search(text)


# -----------------------------
# RELATIVE PATHS
# -----------------------------

@pytest.mark.parametrize("path", [
    r".\payload.exe",
    r"..\lib\config.json",
    r"./run.sh",
    r"../bin/loader.so",
])
def test_relative_matches(path):
    assert RELATIVE_PATH.search(path)


@pytest.mark.parametrize("text", [
    "....\weird.exe",      # too many dots
    "temp/run",            # no extension
])
def test_relative_negative(text):
    assert not RELATIVE_PATH.search(text)


# -----------------------------
# ENVIRONMENT VARIABLE PATHS
# -----------------------------

@pytest.mark.parametrize("path", [
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk",
    r"$HOME/.config/evil.sh",
])
def test_env_matches(path):
    assert ENV_PATH.search(path)


@pytest.mark.parametrize("text", [
    "%NOTCLOSED\path.exe",   # malformed
    "$not valid/path",       # invalid var name
])
def test_env_negative(text):
    assert not ENV_PATH.search(text)


# -----------------------------
# FULL EXTRACTOR TEST
# -----------------------------

def test_full_extractor_combined():
    text = """
        C:\\Windows\\System32\\cmd.exe
        /usr/bin/python
        \\\\SERVER01\\share\\dropper.exe
        ../lib/config.json
        %APPDATA%\\evil.dll
        $HOME/.config/evil.sh
    """

    found = extract(text)

    assert r"C:\Windows\System32\cmd.exe" in found
    assert "/usr/bin/python" in found
    assert r"\\SERVER01\share\dropper.exe" in found
    assert "../lib/config.json" in found
    assert r"%APPDATA%\evil.dll" in found
    assert "$HOME/.config/evil.sh" in found
