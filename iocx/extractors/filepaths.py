import re
from ..detectors import register_detector

# ============================================================
# WINDOWS ABSOLUTE PATHS (supports spaces, prevents substrings)
# ============================================================
WINDOWS_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9])                     # strict boundary
    [A-Za-z]:                            # drive letter
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*         # directories (allow spaces)
    [^\\/:*?"<>|\r\n]+                   # final filename
    (?=$|\s|[.,;:!?])                    # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNC PATHS (supports spaces, prevents substring matches)
# ============================================================
UNC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])                     # strict boundary
    \\\\                                  # leading UNC slashes
    [^\\/:*?"<>|\r\n]+                    # server
    [\\/]
    [^\\/:*?"<>|\r\n]+                    # share
    (?:[\\/][^\\/:*?"<>|\r\n]+)*          # directories
    (?:[\\/][^\\/:*?"<>|\r\n]+)?          # optional final filename
    (?=$|\s|[.,;:!?])                     # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNIX ABSOLUTE PATHS
# ============================================================
UNIX_ABS = re.compile(
    r"""
    (?:
        ^
      | (?<=[\s"'`([{<])
    )
    /
    [^/\r\n]+                # allow spaces inside segments
    (?:/[^/\r\n]+)*          # additional segments
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)

# ============================================================
# RELATIVE PATHS (do NOT match inside absolute/env paths)
# ============================================================
RELATIVE_PATH = re.compile(
    r"""
    (?:
        ^                      # start of string
      | (?<=\n)                # start of new line
      | (?<=\s)(?<![A-Za-z0-9\\/:%$~]\s)   # whitespace, but NOT after a path or alphanumeric char
    )
    (?:
        \.{1,2}[\\/]
      |
        [A-Za-z0-9._~-]+[\\/]
    )
    (?:[^\\/:*?"<>|\r\n]+[\\/])*   # directories
    [^\\/:*?"<>|\r\n\s]+           # final filename
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)

# ============================================================
# ENVIRONMENT VARIABLE PATHS
# ============================================================
ENV_PATH = re.compile(
    r"""
    (?:
        ^
      | (?<=\s)
      | (?<=[\s"'`([{<])
    )
    (
        % [A-Z0-9_]+ %                    # %APPDATA%
        (?: [\\/][^\\/:*?"<>|\r\n]+ )*    # segments

      |
        \$[A-Z_][A-Z0-9_]*                # $HOME
        (?: / [^/\r\n]+ )*                # segments (allow spaces)
    )
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ============================================================
# TILDE PATHS (unchanged logic, but now won't be shadowed by UNIX_ABS)
# ============================================================
TILDE_PATH = re.compile(
    r"""
    (?:
        ^                                  # start of string
      | (?<=[\s"'`([{<])                   # or after whitespace / opening punctuation
    )
    ~[A-Za-z0-9._-]*                       # ~ or ~user
    (?:/[^/\s]+)+                          # one or more segments
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
