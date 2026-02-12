import re

# IPv4: 1.2.3.4
IPV4 = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

# IPv6: simplified matcher (covers most real-world cases)
IPV6 = r"\b(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+\b"

IP_REGEX = re.compile(f"({IPV4}|{IPV6})")

def extract(text: str):
    """Extract IPv4 and IPv6 addresses from text."""
    return IP_REGEX.findall(text)
