import re
from ..detectors import register_detector

# Matches Windows paths like C:\Users\Bob\file.txt
# and Unix paths like /usr/local/bin/script.sh
# Do NOT match if the preceding characters are ://
FILEPATH_REGEX = re.compile(
    r"""
    (
        # UNC paths: \\server\share or //server/share
        (?:\\\\|//)[A-Za-z0-9._-]+(?:\\|/)[^\s"']+
        |
        # Windows drive paths: C:\folder\file  (NO forward slashes)
        [A-Za-z]:\

\[^\s"']+
        |
        # Unix paths, but NOT domain-like paths or URLs
        /(?![A-Za-z0-9.-]+\.[A-Za-z]{2,})(?!/)[^\s"']+
    )
    """,
    re.VERBOSE,
)

def extract(text: str):
    """Extract file paths from text."""
    return FILEPATH_REGEX.findall(text)

# register on import
register_detector("filepaths", extract)
