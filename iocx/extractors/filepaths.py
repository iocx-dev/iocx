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
        ^            # start of string
      | (?<=\s)      # or after any whitespace
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

GENERIC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    [A-Za-z0-9._-]{1,100}              # limit segment length
    (?:/[A-Za-z0-9._-]{1,100}){0,10}   # limit depth
    \.[A-Za-z0-9]{1,6}
    (?![A-Za-z0-9])
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
        GENERIC_PATH,
    ):
        for m in regex.finditer(text):
            value = m.group(0)
            results.append((value, m.start(), m.end(), "filepaths"))

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for value, start, end, category in results:
        if value not in seen:
            seen.add(value)
            deduped.append((value, start, end, category))

    return deduped

register_detector("filepaths", extract)
