import re
from ..detectors import register_detector

# Windows absolute drive paths: C:\Windows\System32\cmd.exe, D:/temp/run.exe
# UNC paths: \\server\share\folder\file.txt
# Unix absolute: /usr/bin/python, /etc/ssh/sshd_config
FILEPATH_REGEX = re.compile(
    r"""
    (?x)
    (
        # Windows drive absolute, e.g. C:\path\file.txt
        [A-Za-z]:[\\/] (?: [^\\/:*?"<>|\r\n]+ [\\/] )* [^\\/:*?"<>|\r\n\s]+
        |
        # UNC path, e.g. \\server\share\path
        \\\\ [^\\\/\s]+ \\ [^\\\/\s]+ (?: \\ [^\\\/\s]+ )*
        |
        # Unix absolute, e.g. /usr/bin/python
        \/(?:[A-Za-z0-9._~-]+\/)+[A-Za-z0-9._~-]+
    )
    """,
    re.VERBOSE,
)

def extract(text: str):
    """Extract file paths from text."""
    return FILEPATH_REGEX.findall(text)

# register on import
register_detector("filepaths", extract)
