# **Load Config Fixture Summary (Valid Fixtures — layer2_edge)**

| Fixture | Description | Output File | Build Command |
|--------|-------------|-------------|----------------|
| **Full MSVC Load Config** | Full modern MSVC structure: SecurityCookie, SEH table, GuardCF fields, function tables | `load_config_full_msvc.full.exe` | `cl /nologo /Ox load_config_full_msvc.full.c` |
| **Minimal MinGW Load Config** | Very small MinGW-style structure (≈0x40 bytes), no cookie, no SEH, no GuardCF | `load_config_minimal_mingw.full.exe` | `cl /nologo /Ox load_config_minimal_mingw.full.c` |
| **Clang/LLVM Load Config** | Mid-sized structure: SecurityCookie + GuardCF fields, no SEH table | `load_config_clang.full.exe` | `cl /nologo /Ox load_config_clang.full.c` |
| **Large Padded Load Config** | Oversized but valid structure with padding; only cookie meaningful | `load_config_large_padded.full.exe` | `cl /nologo /Ox load_config_large_padded.full.c` |
| **Load Config with SEH Table** | Valid SEH table + SecurityCookie; no GuardCF | `load_config_seh_table.full.exe` | `cl /nologo /Ox load_config_seh_table.full.c` |
| **Cookie‑Valid Load Config** | Minimal valid structure containing only SecurityCookie | `load_config_cookie_valid.full.exe` | `cl /nologo /Ox load_config_cookie_valid.full.c` |
