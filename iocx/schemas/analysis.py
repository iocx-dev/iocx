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

class LoadConfigInfo(TypedDict, total=False):
    # Number of bytes successfully parsed from the structure
    parsed_size: int

    # Security cookie
    security_cookie_rva: int | None

    # SEH table
    seh_table_rva: int | None
    seh_count: int | None

    # Guard CF metadata
    guard_cf_check_function_pointer: int | None
    guard_cf_dispatch_function_pointer: int | None
    guard_cf_function_table: int | None
    guard_cf_function_count: int | None

    # Optional fields (ignored by validator but preserved for completeness)
    time_date_stamp: int | None
    guard_flags: int | None

class AnalysisDict(TypedDict):
    sections: List[SectionInfo]
    data_directories: List[DataDirectoryInfo]
    extended: List[ExtendedDetection]
    obfuscation: List[ObfuscationHint]
    file_size: int
    overlay_offset: int
    load_config: LoadConfigInfo | None
