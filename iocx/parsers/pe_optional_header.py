# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

def extract_optional_header_metadata(pe) -> dict:
    magic = getattr(pe.OPTIONAL_HEADER, "Magic", None)
    num_rva_and_sizes = getattr(pe.OPTIONAL_HEADER, "NumberOfRvaAndSizes", None)
    if not isinstance(magic, int):
        magic = None
    if not isinstance(num_rva_and_sizes, int):
        num_rva_and_sizes = None

    return {
        "optional_header_magic": magic,
        "number_of_rva_and_sizes": num_rva_and_sizes,
    }
