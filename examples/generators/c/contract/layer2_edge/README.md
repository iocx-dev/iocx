# **Load Config Fixture Summary (Valid Fixtures — layer2_edge)**

| Fixture | Description | Output File | Build Command |
|--------|-------------|-------------|----------------|
| **Full MSVC Load Config** | Full modern MSVC structure: SecurityCookie, SEH table, GuardCF fields, function tables | `loadcfg_full_msvc.full.exe` | `cl /nologo /Ox loadcfg_full_msvc.c` |
| **Minimal MinGW Load Config** | Very small MinGW-style structure (≈0x40 bytes), no cookie, no SEH, no GuardCF | `loadcfg_minimal_mingw.full.exe` | `cl /nologo /Ox loadcfg_minimal_mingw.c` |
| **Clang/LLVM Load Config** | Mid-sized structure: SecurityCookie + GuardCF fields, no SEH table | `loadcfg_clang.full.exe` | `cl /nologo /Ox loadcfg_clang.c` |
| **Large Padded Load Config** | Oversized but valid structure with padding; only cookie meaningful | `loadcfg_large_padded.full.exe` | `cl /nologo /Ox loadcfg_large_padded.c` |
| **Load Config with SEH Table** | Valid SEH table + SecurityCookie; no GuardCF | `loadcfg_seh_table.full.exe` | `cl /nologo /Ox loadcfg_seh_table.c` |
| **Cookie‑Only Load Config** | Minimal valid structure containing only SecurityCookie | `loadcfg_cookie_only.full.exe` | `cl /nologo /Ox loadcfg_cookie_only.c` |
