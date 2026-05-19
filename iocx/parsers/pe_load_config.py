# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from ..schemas.analysis import LoadConfigInfo

def analyse_load_config(pe, data_directories) -> LoadConfigInfo:
    """
    Extract IMAGE_LOAD_CONFIG_DIRECTORY info.

    ALWAYS returns a dict so the validator can run truncation logic.

    Note: We compute available bytes from the actual file size, not section raw size.
          Section metadata may be padded or incorrect, but the file length is always authoritative.
    """

    # ---------------------------------------------------------
    # Find the load config directory entry
    # ---------------------------------------------------------
    lcd = next(
        (
            d for d in data_directories
            if d.get("name") == "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"
            or d.get("index") == 10
        ),
        None,
    )

    if not lcd:
        return {"parsed_size": 0}

    rva = lcd.get("rva")
    declared_size = lcd.get("size")

    if not isinstance(rva, int) or not isinstance(declared_size, int):
        return {"parsed_size": 0}
    if rva == 0:
        return {"parsed_size": 0}

    # ---------------------------------------------------------
    # Map RVA → raw offset
    # ---------------------------------------------------------
    raw_offset = None

    # Range check
    size_of_image = getattr(pe.OPTIONAL_HEADER, "SizeOfImage", None)
    if size_of_image is not None and (rva < 0 or rva >= size_of_image):
        raw_offset = None
    else:
        try:
            raw_offset = pe.get_offset_from_rva(rva)
        except PEFormatError:
            raw_offset = None

    if raw_offset is None:
        # Unmapped directory: nothing parseable, but we still return a dict
        # so the validator can flag "unmapped" / "negative RVA" etc.
        parsed_size = 0
    else:
        # ---------------------------------------------------------
        # Compute available bytes from actual file size
        # ---------------------------------------------------------
        file_end = len(pe.__data__)
        available = max(0, file_end - raw_offset)

        # parsed_size = what we COULD have parsed
        parsed_size = min(available, max(0, declared_size))

    # ---------------------------------------------------------
    # Try to extract fields from pefile if available
    # ---------------------------------------------------------
    try:
        lcd_struct = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    except Exception:
        lcd_struct = None

    def get(field):
        return getattr(lcd_struct, field, None) if lcd_struct else None

    return {
        "parsed_size": parsed_size,

        "security_cookie_rva": get("SecurityCookie") or None,

        "seh_table_rva": get("SEHandlerTable"),
        "seh_count": get("SEHandlerCount"),

        "guard_cf_check_function_pointer": get("GuardCFCheckFunctionPointer"),
        "guard_cf_dispatch_function_pointer": get("GuardCFDispatchFunctionPointer"),
        "guard_cf_function_table": get("GuardCFFunctionTable"),
        "guard_cf_function_count": get("GuardCFFunctionCount"),

        "time_date_stamp": get("TimeDateStamp"),
        "guard_flags": get("GuardFlags"),
    }
