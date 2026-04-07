from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

@dataclass
class Detection:
    value: str
    start: str
    end: int
    category: str
    metadata: dict | None = None

@dataclass
class PluginContext:
    file_path: Path
    raw_text: str
    logger: Any
    config: Dict[str, Any]
    detections: Dict[str, Any]
    engine: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
