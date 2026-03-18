from dataclasses import dataclass

@dataclass
class Detection:
    value: str
    start: str
    end: int
    category: str
