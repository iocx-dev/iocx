import re
from ..detectors import register_detector

# ============================================================
# WINDOWS ABSOLUTE PATHS
# ============================================================
WINDOWS_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9])
    [A-Za-z]:
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*       # directories (allow spaces)
    [^\\/:*?"<>|\r\n]*?                # filename base (allow spaces)
    \.[A-Za-z0-9]{1,6}                 # extension
    (?=$|\s|[.,;:!?])                  # boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNC PATHS
# ============================================================
UNC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    \\\\
    [^\\/:*?"<>|\r\n]+
    [\\/]
    [^\\/:*?"<>|\r\n]+
    (?:[\\/][^\\/:*?"<>|\r\n]+)*
    [^\\/:*?"<>|\r\n]*?
    \.[A-Za-z0-9]{1,6}
    (?=$|\s|[.,;:!?])
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
    [^/\r\n]+
    (?:/[^/\r\n]+)*
    """,
    re.VERBOSE,
)

# ============================================================
# RELATIVE PATHS
# ============================================================
RELATIVE_PATH = re.compile(
    r"""
    (?:
        ^
      | (?<=\s)
    )
    (?:
        \.{1,2}[\\/]
      |
        [A-Za-z0-9._~-]+[\\/]
    )
    (?:[^\\/:*?"<>|\r\n]+[\\/])*
    [^\\/:*?"<>|\r\n\s]+
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
        (?: [\\/][^\\/:*?"<>|\r\n]+ )*
      |
        \$[A-Z_][A-Z0-9_]*                # $HOME
        (?: / [^/\r\n]+ )*
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ============================================================
# TILDE PATHS
# ============================================================
TILDE_PATH = re.compile(
    r"""
    (?:
        ^
      | (?<=[\s"'`([{<])
    )
    ~[A-Za-z0-9._-]*
    (?:/[^/\s]+)+
    """,
    re.VERBOSE,
)

# ============================================================
# GENERIC EXTENSION PATHS
# ============================================================
GENERIC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    [A-Za-z0-9._-]{1,100}
    (?:/[A-Za-z0-9._-]{1,100})+      # <-- require at least ONE slash
    \.[A-Za-z0-9]{1,6}
    (?=$|\s|[.,;:!?])
    """,
    re.VERBOSE,
)


# ============================================================
# Extractor
# ============================================================
def extract(text: str):
    results = []

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
            start = m.start()
            end = m.end()
            results.append((value, start, end, "filepaths"))

    # Deduplicate by value
    seen = set()
    deduped = []
    for value, start, end, category in results:
        if value not in seen:
            seen.add(value)
            deduped.append((value, start, end, category))

    return deduped


register_detector("filepaths", extract)
