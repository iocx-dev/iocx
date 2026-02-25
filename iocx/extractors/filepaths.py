import re
from ..detectors import register_detector

# ============================================================
# WINDOWS ABSOLUTE PATHS (supports spaces)
# ============================================================
WINDOWS_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9])                 # boundary
    [A-Za-z]:                        # drive letter
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*     # directories (allow spaces)
    [^\\/:*?"<>|\r\n\s]+             # final filename (no spaces)
    (?=$|\s|[.,;:!?])                # end boundary
    """,
    re.VERBOSE,
)


# ============================================================
# UNC PATHS
# ============================================================
UNC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    \\\\                              # \\server
    [A-Za-z0-9._-]+                   # server or IP
    [\\/]
    [A-Za-z0-9._$-]+                  # share
    (?:[\\/][^\\/:*?"<>|\r\n]+)*      # directories (allow spaces)
    [\\/]
    [^\\/:*?"<>|\r\n\s]+              # final filename (NO spaces)
    (?=$|\s|[.,;:!?])                 # end boundary
    """,
    re.VERBOSE,
)



# ============================================================
# UNIX ABSOLUTE PATHS (no Windows drive letters)
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
# RELATIVE PATHS (strict, no trailing text)
# ============================================================
RELATIVE_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9._-])
    (?:\.{1,2}[\\/])
    (?:[^\\/:*?"<>|\r\n]+[\\/])*      # directories
    [^\\/:*?"<>|\r\n]+                # final filename
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)

# ============================================================
# ENVIRONMENT VARIABLE PATHS
# ============================================================
ENV_PATH = re.compile(
    r"""
    (
        % [A-Z0-9_]+ %                # %APPDATA%
        (?: [\\/][^\\/:*?"<>|\r\n]+ )+
      |
        \$[A-Z_][A-Z0-9_]*            # $HOME
        (?: / [A-Za-z0-9._~-]+ )+
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
            # Some regexes return tuples; flatten them
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
