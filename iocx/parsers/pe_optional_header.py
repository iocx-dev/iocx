# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

def extract_optional_header_metadata(pe) -> dict:
    magic = getattr(pe.OPTIONAL_HEADER, "Magic", None)
    if not isinstance(magic, int):
        magic = None

    return {
        "optional_header_magic": magic,
    }
