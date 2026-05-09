# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import re
from ..registry import register_detector
from ...models import Detection

# ============================================================
# WINDOWS ABSOLUTE PATHS (supports spaces in directories)
# ============================================================
WINDOWS_ABS = re.compile(
    r"""
    (?<![A-Za-z0-9])                 # boundary
    [A-Za-z]:                        # drive letter
    [\\/]
    (?:[^\\/:*?"<>|\r\n]+[\\/])*     # directories (allow spaces)
    [^\\/:*?"<>|\r\n\s]+             # final filename (NO spaces)
    (?=$|\s|[.,;:!?])                # end boundary
    """,
    re.VERBOSE,
)

# ============================================================
# UNC PATHS (no whitespace in share or directory segments)
# ============================================================
UNC_PATH = re.compile(
    r"""
    (?<![A-Za-z0-9])
    \\\\                              # \\server
    [A-Za-z0-9._-]+                   # server or IP
    [\\/]
    [A-Za-z0-9._$-]+                  # share
    (?:[\\/][^\\/:*?"<>|\r\n\s]+)*    # directories (NO whitespace)
    [\\/]
    [^\\/:*?"<>|\r\n\s]+              # final filename (NO whitespace)
    (?=$|\s|[.,;:!?])                 # end boundary
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
    results: list[Detection] = []

    # Order matters — Windows first, then UNC, then Unix, etc.
    for regex in (
        WINDOWS_ABS,
        UNC_PATH,
        UNIX_ABS,
        RELATIVE_PATH,
        TILDE_PATH,
        ENV_PATH,
    ):
        for m in regex.finditer(text):
            results.append(
                Detection(
                    value=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    category="filepaths",
                )
            )

    return results


register_detector("filepaths", extract)
