import re

URL_REGEX = re.compile(
    r"(https?://[^\s\"'<>]+)",
    re.IGNORECASE
)

def extract(text):
    return URL_REGEX.findall(text)
