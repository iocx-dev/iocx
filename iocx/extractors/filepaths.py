import re
from ..detectors import register_detector

# Matches Windows paths like C:\Users\Bob\file.txt
# and Unix paths like /usr/local/bin/script.sh
FILEPATH_REGEX = re.compile(
    r"([A-Za-z]:\\[^\s\"']+|\/[^\s\"']+)"
)

def extract(text: str):
    """Extract file paths from text."""
    return FILEPATH_REGEX.findall(text)

# register on import
register_detector("filepaths", extract)
