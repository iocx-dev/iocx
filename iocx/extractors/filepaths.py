import re
from ..detectors import register_detector

# -----------------------------
# Windows absolute paths
# -----------------------------
WINDOWS_ABS = re.compile(
    r"""
    \b
    [A-Z]:[\\/]
    (?:
        [^\\/:*?"<>|\r\n]+[\\/]      # directories
    )*
    [^\\/:*?"<>|\r\n]+              # final filename
    """,
    re.VERBOSE | re.IGNORECASE,
)

# -----------------------------
# UNC paths
# -----------------------------
UNC_PATH = re.compile(
    r"""
    \\\\                                # leading UNC slashes
    [A-Z0-9._-]+                        # server or IP
    [\\/]                               # separator
    [A-Z0-9._$-]+                       # share name (allow $)
    (?:
        [\\/] [^\\/:*?"<>|\r\n]+
    )*
    """,
    re.VERBOSE | re.IGNORECASE,
)

# -----------------------------
# Unix absolute paths
# -----------------------------
UNIX_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9._-])        # not inside a word or domain
    /
    (?:[A-Za-z0-9._~-]+/)+     # one or more directories, each ending with /
    [A-Za-z0-9._~-]+           # final filename (no trailing slash)
    (?![A-Za-z0-9._-])         # don't bleed into domains
    """,
    re.VERBOSE,
)

# -----------------------------
# Relative paths
# -----------------------------
RELATIVE_PATH = re.compile(
    r"(?<![A-Za-z0-9._-])"
    r"(?:\.{1,2}[\\/])"
    r"(?:[^\\/:*?\"<>|\r\n]+[\\/])*"
    r"[^\\/:*?\"<>|\r\n]+(?:\.[A-Za-z0-9]{1,10})?",
    re.IGNORECASE,
)

# -----------------------------
# Environment variable paths
# -----------------------------
ENV_PATH = re.compile(
    r"""
    (
        % [A-Z0-9_]+ %                  # %APPDATA%
        (?: [\\/][^\\/:*?"<>|\r\n]+ )+
      |
        \$[A-Z_][A-Z0-9_]*              # $HOME
        (?: / [A-Za-z0-9._~-]+ )+       # allow .config, etc.
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

TILDE_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9._-])
    ~[A-Za-z0-9._-]*              # ~ or ~username
    (?:/[A-Za-z0-9._~-]+)+        # /path/segments
    """,
    re.VERBOSE,
)


# -----------------------------
# Extractor
# -----------------------------
def extract(text: str):
    results = []

    for regex in (WINDOWS_ABS, UNC_PATH, UNIX_ABS, RELATIVE_PATH, TILDE_PATH, ENV_PATH):
        results.extend(regex.findall(text))

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for r in results:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped


register_detector("filepaths", extract)
