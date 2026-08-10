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


# ------------------------
# Exports schema
# ------------------------

class ExportFunctionEntry(TypedDict):
    index: int
    ordinal: int
    address_rva: Optional[int]
    is_forwarder: bool
    forwarder: Optional[str]
    forwarder_valid: bool
    name: Optional[str]
    name_rva: Optional[int]


class ExportNamePointerEntry(TypedDict):
    index: int
    name_rva: Optional[int]
    ordinal_index: Optional[int]
    name: Optional[str]
    name_valid: bool
    errors: List[str]


class ExportDirectoryHeader(TypedDict):
    Characteristics: int
    TimeDateStamp: int
    MajorVersion: int
    MinorVersion: int
    Name: int
    Base: int
    NumberOfFunctions: int
    NumberOfNames: int
    AddressOfFunctions: int
    AddressOfNames: int
    AddressOfNameOrdinals: int


class ExportStruct(TypedDict, total=False):
    rva: int
    size: int
    header: Optional[ExportDirectoryHeader]
    functions: List[ExportFunctionEntry]
    name_pointers: List[ExportNamePointerEntry]
    truncations: List[str]
    errors: List[str]


# -------------------------
# Delay-load import
# -------------------------

class DelayImportEntry(TypedDict, total=False):
    index: int
    is_ordinal: bool
    ordinal: Optional[int]
    hint: Optional[int]
    name: Optional[str]
    name_rva: Optional[int]
    name_valid: bool
    iat_value: Optional[int]
    errors: List[str]


class DelayImportDescriptor(TypedDict, total=False):
    index: int
    attributes: int
    attributes_v1: bool
    dll_name_rva: int
    dll_name: Optional[str]
    dll_name_valid: bool
    module_handle_rva: int
    iat_rva: int
    int_rva: int
    bound_iat_rva: int
    unload_iat_rva: int
    timestamp: int
    is_bound: bool # derived: True if bound_iat_rva != 0
    imports: List[DelayImportEntry]
    errors: List[str]


class DelayImportStruct(TypedDict, total=False):
    rva: int
    size: int
    is_64bit: bool
    descriptors: List[DelayImportDescriptor]
    truncations: List[str]
    errors: List[str]


# -------------------------
# Relocation table
# -------------------------

class RelocationEntry(TypedDict):
    type: int
    type_name: Optional[str]  # IMAGE_REL_BASED_* name, None if unknown
    offset: int               # 12-bit offset within the page
    rva: int                  # derived: page_rva + offset


class RelocationBlock(TypedDict):
    index: int
    block_rva: int            # RVA of this IMAGE_BASE_RELOCATION header
    page_rva: int             # VirtualAddress field (base of the 4 KiB page)
    size_of_block: int        # SizeOfBlock field (header + entries)
    entry_count: int          # derived: number of decoded entries
    entries: List[RelocationEntry]
    errors: List[str]


class RelocationStruct(TypedDict, total=False):
    rva: int
    size: int
    blocks: List[RelocationBlock]
    block_count: int          # derived: len(blocks)
    entry_count: int          # derived: total entries across all blocks
    truncations: List[str]
    errors: List[str]


# -------------------------
# Certificate table
# -------------------------

class CertificateEntry(TypedDict):
    index: int
    offset: int                    # file offset of this WIN_CERTIFICATE
    length: int                    # dwLength (incl. 8-byte header)
    revision: int
    revision_name: Optional[str]   # WIN_CERT_REVISION_* name, None if unknown
    cert_type: int
    cert_type_name: Optional[str]  # WIN_CERT_TYPE_* name, None if unknown
    data_length: int               # derived: bCertificate payload length
    errors: List[str]


class CertificateStruct(TypedDict, total=False):
    offset: int                          # file offset (NOT an RVA) per WIN_CERTIFICATE
    size: int
    file_size: Optional[int]             # backing file length, None if unavailable
    image_raw_end: Optional[int]         # max(PointerToRawData + SizeOfRawData)
    overlaps_image: Optional[bool]       # offset < image_raw_end (defect if True)
    certificates: List[CertificateEntry]
    certificate_count: int               # derived: len(certificates)
    truncations: List[str]
    errors: List[str]


# -------------------------
# Debug directory
# -------------------------

class DebugEntry(TypedDict, total=False):
    index: int
    characteristics: int
    timestamp: int                  # TimeDateStamp
    major_version: int
    minor_version: int
    type: int
    type_name: Optional[str]        # IMAGE_DEBUG_TYPE_* name, None if unknown
    size_of_data: int
    address_of_raw_data: int        # RVA of the debug data
    pointer_to_raw_data: int        # file offset of the debug data
    pdb_path: Optional[str]         # CodeView only; None otherwise
    cv_signature: Optional[str]     # "RSDS" | "NB10" | None
    guid: Optional[str]             # RSDS only; canonical mixed-endian
    age: Optional[int]              # CodeView only
    errors: List[str]


class DebugStruct(TypedDict, total=False):
    rva: int
    size: int
    entries: List[DebugEntry]
    entry_count: int          # derived: len(entries)
    truncations: List[str]
    errors: List[str]


# -------------------------
# TLS directory
# -------------------------

class TlsStruct(TypedDict, total=False):
    rva: int
    size: int
    is_64bit: bool
    image_base: Optional[int]                  # OPTIONAL_HEADER.ImageBase
    start_address_of_raw_data: Optional[int]   # VA
    end_address_of_raw_data: Optional[int]     # VA
    address_of_index: Optional[int]            # VA
    address_of_callbacks: Optional[int]        # VA of the callback array
    size_of_zero_fill: Optional[int]
    characteristics: Optional[int]
    raw_data_size: Optional[int]               # derived: end - start; None if end < start
    callbacks: List[int]                       # resolved callback VAs (NULL-terminated)
    callback_count: int                        # derived: len(callbacks)
    truncations: List[str]
    errors: List[str]


# -------------------------
# Internal metadata schema
# -------------------------

class InternalMetadata(TypedDict, total=False):
    resources_struct: Optional[ResourcesStruct]
    version_info_struct: Optional[VersionInfoStruct]
    data_directories_raw: List[DataDirectoryRaw]
    export_struct: Optional[ExportStruct]
    delay_import_struct: Optional[DelayImportStruct]
    relocation_struct: Optional[RelocationStruct]
    certificate_struct: Optional[CertificateStruct]
    debug_struct: Optional[DebugStruct]
    tls_struct: Optional[TlsStruct]
    optional_header_magic: int
    number_of_rva_and_sizes: int
