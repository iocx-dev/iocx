# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import TypedDict, List, Dict, Any

# -------------------------
# Resource directory schema
# -------------------------

class ResourceDirectoryNode(TypedDict):
    rva: int
    size: int
    entries: List[Any] # directory or data entries


class ResourceDataEntry(TypedDict):
    is_directory: bool
    data_rva: int
    data_size: int
    raw_offset: int


class ResourceDirectoryEntry(TypedDict):
    is_directory: bool
    directory: ResourceDirectoryNode


class ResourceStringTable(TypedDict):
    rva: int
    size: int


class ResourcesStruct(TypedDict):
    root: ResourceDirectoryNode
    string_tables: List[ResourceStringTable]


# -------------------------
# Internal metadata schema
# -------------------------

class InternalMetadata(TypedDict, total=False):
    resources_struct: ResourcesStruct
