# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import TypedDict, List, Dict, Any, Optional, Tuple

# -------------------------
# Resource directory schema
# -------------------------

class ResourceEntry(TypedDict):
    name: Optional[str]
    id: Optional[int]
    is_directory: bool
    directory: Optional["ResourceDirectoryNode"]
    data_rva: Optional[int]
    data_size: Optional[int]
    raw_offset: Optional[int]


class ResourceDirectoryNode(TypedDict):
    rva: int
    size: int
    entries: List[ResourceEntry]


class ResourceStringTable(TypedDict):
    rva: int
    size: int


class ResourcesStruct(TypedDict):
    root: ResourceDirectoryNode
    string_tables: List[ResourceStringTable]


# -------------------------
# Version-info schema
# -------------------------

class Translation(TypedDict):
    lang: int
    codepage: int


class VarEntry(TypedDict):
    key: str
    translations: List[Translation]


class VarFileInfo(TypedDict):
    vars: List[VarEntry]
    errors: List[str]


class StringTable(TypedDict):
    lang_codepage: str
    strings: Dict[str, str]
    errors: List[str]


class StringFileInfo(TypedDict):
    tables: List[StringTable]
    errors: List[str]


class FixedFileInfo(TypedDict):
    signature: int
    signature_ok: bool
    struct_version: int
    struct_version_ok: bool
    file_version: Tuple[int, int]
    product_version: Tuple[int, int]
    file_flags_mask: int
    file_flags: int
    file_os: int
    file_type: int
    file_subtype: int
    file_date: Tuple[int, int]


class VersionInfoStruct(TypedDict, total=False):
    rva: Optional[int]
    size: Optional[int]
    decoded: bool
    header_ok: bool
    length_consistent: bool
    w_type: Optional[int]
    fixed_file_info: Optional[FixedFileInfo]
    string_file_info: List[StringFileInfo]
    var_file_info: List[VarFileInfo]
    errors: List[str]


# -------------------------
# Data directory schema
# -------------------------

class DataDirectoryRaw(TypedDict):
    index: int
    name: Optional[str]
    rva: int
    size: int


# -------------------------
# Internal metadata schema
# -------------------------

class InternalMetadata(TypedDict, total=False):
    resources_struct: Optional[ResourcesStruct]
    version_info_struct: Optional[VersionInfoStruct]
    data_directories_raw: List[DataDirectoryRaw]
    optional_header_magic: int
    number_of_rva_and_sizes: int
