import re

PATTERNS = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.]", re.IGNORECASE), "."),
    (re.compile(r"\(\.\)", re.IGNORECASE), "."),
    (re.compile(r"\[:]", re.IGNORECASE), ":"),
    (re.compile(r"\[://]", re.IGNORECASE), "://"),
]

def deobfuscate_text(text: str) -> str:
    result = text
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)
    return result
