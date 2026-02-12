import re

DOMAIN_REGEX = re.compile(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

def extract(text):
    return DOMAIN_REGEX.findall(text)
