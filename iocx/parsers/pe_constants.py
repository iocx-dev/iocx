# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Constant lookup tables for Optional Header field decoding.
Sources: Microsoft PE format specification, winnt.h.
"""

# IMAGE_SUBSYSTEM_* values per PE spec
SUBSYSTEM_NAMES = {
    0:  "UNKNOWN",
    1:  "NATIVE",
    2:  "WINDOWS_GUI",
    3:  "WINDOWS_CUI",
    5:  "OS2_CUI",
    7:  "POSIX_CUI",
    8:  "NATIVE_WINDOWS",
    9:  "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

# IMAGE_DLLCHARACTERISTICS_* bit flags
DLL_CHARACTERISTICS_FLAGS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

# Moved from extended layer
MACHINE_NAMES = {
    0x014c: "x86",
    0x8664: "AMD64",
    0x0200: "IA64",
}

# Mask covering all known DLL characteristics bits
DLL_CHARACTERISTICS_KNOWN_MASK = 0
for _bit in DLL_CHARACTERISTICS_FLAGS:
    DLL_CHARACTERISTICS_KNOWN_MASK |= _bit
