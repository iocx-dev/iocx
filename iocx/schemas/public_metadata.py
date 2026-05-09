from typing import TypedDict, List, Dict, Any, Optional


class TLSInfo(TypedDict, total=False):
    start_address: Optional[int]
    end_address: Optional[int]
    callbacks: Optional[List[int]]


class HeaderInfo(TypedDict, total=False):
    entry_point: Optional[int]
    image_base: Optional[int]
    subsystem: Optional[int]
    timestamp: Optional[int]
    machine: Optional[int]
    characteristics: Optional[int]


class OptionalHeaderInfo(TypedDict, total=False):
    section_alignment: Optional[int]
    file_alignment: Optional[int]
    size_of_image: Optional[int]
    size_of_headers: Optional[int]
    linker_version: Optional[str]
    os_version: Optional[str]
    subsystem_version: Optional[str]


class RichHeaderInfo(TypedDict, total=False):
    # Rich headers vary widely; keep flexible
    raw: Any
    decoded: Any


class ImportEntry(TypedDict):
    dll: str
    function: Optional[str]
    ordinal: Optional[int]


class ExportEntry(TypedDict):
    name: Optional[str]
    ordinal: Optional[int]
    forwarder: Optional[str]


class ResourceEntry(TypedDict):
    type: str
    name: Optional[str]
    language: Optional[str]
    size: int
    entropy: float
    rva: int
    raw_offset: int


class PublicMetadata(TypedDict, total=False):
    file_type: str

    # High‑level lists
    imports: List[str]
    sections: List[Dict[str, Any]]
    resources: List[ResourceEntry]
    resource_strings: List[str]

    # Detailed import structures
    import_details: List[ImportEntry]
    delayed_imports: List[ImportEntry]
    bound_imports: List[Dict[str, Any]]

    # Exports
    exports: List[ExportEntry]

    # TLS
    tls: TLSInfo

    # Headers
    header: HeaderInfo
    optional_header: OptionalHeaderInfo
    rich_header: Optional[RichHeaderInfo]

    # Signatures
    signatures: List[Dict[str, Any]]
    has_signature: bool
