# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import TypedDict, List, Dict, Any

class SectionInfo(TypedDict):
    name: str
    raw_size: int
    virtual_size: int
    characteristics: int
    entropy: float
    raw_address: int
    virtual_address: int

class DataDirectoryInfo(TypedDict):
    index: int
    name: str | None
    rva: int
    size: int

class ObfuscationHint(TypedDict):
    value: str
    start: int
    end: int
    category: str
    metadata: Dict[str, Any]

class ExtendedDetection(TypedDict):
    value: str
    start: int
    end: int
    category: str
    metadata: Dict[str, Any]

class AnalysisDict(TypedDict):
    sections: List[SectionInfo]
    data_directories: List[DataDirectoryInfo]
    extended: List[ExtendedDetection]
    obfuscation: List[ObfuscationHint]
    file_size: int
    overlay_offset: int
