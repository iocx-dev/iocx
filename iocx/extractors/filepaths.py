import re
from ..detectors import register_detector

# ============================================================
# WINDOWS ABSOLUTE PATHS (supports spaces in directories and filenames)
# ============================================================
WINDOWS_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9])                           # boundary
    [A-Za-z]:                                  # drive letter
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*               # directories (allow spaces)
    (?:[^\\/:*?"<>|\r\n ]+|(?: [ ](?!\S) ))+   # filename with safe internal spaces
    (?=\s|$|[.,;:!?])                          # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNC PATHS (no whitespace in share or directory segments)
# ============================================================
UNC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    \\\\                                       # leading UNC slashes
    [A-Za-z0-9._-]+                            # server name or IP
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*               # share + directories (allow spaces)
    (?:[^\\/:*?"<>|\r\n ]+|(?: [ ](?!\S) ))+   # final filename with safe internal spaces
    (?=\s|$|[.,;:!?])                          # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNIX ABSOLUTE PATHS (strict, no Windows drive letters)
# ============================================================
UNIX_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9._-])               # boundary
    /
    (?:[A-Za-z0-9._~-]+/)+            # directories
    [A-Za-z0-9._~-]+                  # final filename
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)

# ============================================================
# RELATIVE PATHS (no whitespace in final filename)
# ============================================================
RELATIVE_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9._-])
    (?:\.{1,2}[\\/])
    (?:[^\\/:*?"<>|\r\n]+[\\/])*      # directories (allow spaces)
    [^\\/:*?"<>|\r\n\s]+              # final filename (NO whitespace)
    (?=$|\s|[.,;:!?])                 # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# ENVIRONMENT VARIABLE PATHS (no whitespace in final filename)
# ============================================================
ENV_PATH = re.compile(
    r"""
    (
        % [A-Z0-9_]+ %                # %APPDATA%
        (?: [\\/][^\\/:*?"<>|\r\n]+ )*
        [\\/][^\\/:*?"<>|\r\n\s]+     # final filename (NO whitespace)
      |
        \$[A-Z_][A-Z0-9_]*            # $HOME
        (?: / [A-Za-z0-9._~-]+ )*
        / [A-Za-z0-9._~-]+            # final filename
    )
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ============================================================
# TILDE PATHS
# ============================================================
TILDE_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9._-])
    ~[A-Za-z0-9._-]*                  # ~ or ~user
    (?:/[A-Za-z0-9._~-]+)+            # /path/segments
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)

# ============================================================
# Extractor
# ============================================================
def extract(text: str):
    results = []

    # Order matters — Windows first, then UNC, then Unix, etc.
    for regex in (
        WINDOWS_ABS,
        UNC_PATH,
        UNIX_ABS,
        RELATIVE_PATH,
        TILDE_PATH,
        ENV_PATH,
    ):
        for match in regex.findall(text):
            if isinstance(match, tuple):
                match = match[0]
            results.append(match)

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for r in results:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped


register_detector("filepaths", extract)
