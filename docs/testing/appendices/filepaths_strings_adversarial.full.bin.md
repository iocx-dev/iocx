# Appendix 3.20 — Filepaths Strings Adversarial Specification

- **File:** `filepaths_strings_adversarial.full.bin`
- **Layer: 3** — `Adversarial`

# Purpose

This fixture exercises IOCX’s **filepath extractor** against a mix of:

- valid Windows, UNC, Unix, relative, tilde, and env‑var paths
- split‑line paths
- URL‑like strings
- log keys and garbage with path‑like fragments

The extractor is intentionally permissive and syntax‑driven: any substring that looks like a path according to its patterns is extracted, even if it is only a fragment (e.g. split across lines or truncated before a space).

# Expected matches

The following categories must be extracted as filepaths:

## 1. Windows absolute paths (files and executables)

- `C:\Users\Public\document.txt`
- `D:\Program Files\App\bin.exe`
- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\wscript.exe`
- `C:\Windows\System32\mshta.exe`
- `C:\Windows\System32evil` (syntactically valid, no extension required)

## 2. UNC paths

- `\\server01\share\folder\file.log`
- `\\10.0.0.5\data$\dump.bin`

## 3. Unix absolute paths

- `/usr/local/bin/script.sh`
- `/opt/app/config.yaml`
- `/usr/bin/python3.11`
- `/usr/bin/openssl` (no extension, still treated as a valid path)

## 4. Relative paths

- `.\temp\run.cmd`
- `../logs/error.log`

## 5. Tilde and environment‑variable paths

- `~/projects/code/main.py`
- `~user/docs/readme.md`
- `%APPDATA%\MyApp\config.json`
- `$HOME/.config/tool/settings.ini`

## 6. Split‑line paths (partial fragments)

For these inputs:
```
C:\Users\Pubn\lic\broken.txt
/usr/loc\nal/bin/bad.sh
```

the extractor matches the first syntactically valid fragment on each split:

- `C:\Users\Pub`
- `/usr/loc`

This behaviour is intentional: the extractor does not reconstruct across newlines; it simply extracts what looks like a path up to the break.

## 7. Paths truncated at spaces

For:

```
C:\Temp\my file.txt
/var/log/my file.log
```

the extractor stops at the first space and extracts:

- `C:\Temp\my`
- `/var/log/my`

Spaces are treated as hard terminators for filepath tokens.

# Expected non‑matches

The following inputs must not be classified as filepaths:

- `network.connection.error`
- `auth.failure.reason`
- dotted log keys, no leading drive/UNC/tilde/slash
- `xxx/usr/local/binxxx`
- embedded path‑like fragment inside a larger token
- `http://example.com/path/file.txt` (classified as a URL, not a filepath; appears under urls)

# Design philosophy

The filepath extractor:

- accepts Windows, UNC, Unix, relative, tilde, and env‑var styles
- does not require file extensions
- allows executables and directories with no extension
- treats spaces as terminators for path tokens
- does not reconstruct paths across newlines, but does extract valid leading fragments
- ignores embedded path‑like substrings inside larger tokens
- defers URL‑like strings to the URL detector

This permissive, syntax‑first behaviour is intentional and matches real‑world DFIR expectations:
extract anything that looks like a path, even if it’s partial, and let higher layers decide how to use it.
