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

# Moved from extended layer - expanded to cover the full PE spec
MACHINE_NAMES = {
    0x0000: "UNKNOWN",
    0x014C: "I386",
    0x0162: "R3000",
    0x0166: "R4000",
    0x0168: "R10000",
    0x0169: "WCEMIPSV2",
    0x0184: "ALPHA",
    0x01A2: "SH3",
    0x01A3: "SH3DSP",
    0x01A6: "SH4",
    0x01A8: "SH5",
    0x01C0: "ARM",
    0x01C2: "THUMB",
    0x01C4: "ARMNT",
    0x01D3: "AM33",
    0x01F0: "POWERPC",
    0x01F1: "POWERPCFP",
    0x0200: "IA64",
    0x0266: "MIPS16",
    0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16",
    0x0EBC: "EBC",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
    0x5128: "RISCV128",
    0x6232: "LOONGARCH32",
    0x6264: "LOONGARCH64",
    0x8664: "AMD64",
    0xAA64: "ARM64",
    0xC0EE: "CEE",
}

# Mask covering all known DLL characteristics bits
DLL_CHARACTERISTICS_KNOWN_MASK = 0
for _bit in DLL_CHARACTERISTICS_FLAGS:
    DLL_CHARACTERISTICS_KNOWN_MASK |= _bit
