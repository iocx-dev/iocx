import pefile

def parse_pe(path):
    try:
        # fast_load=True avoids parsing every directory up front, which is ideal for performance and for untrusted files.
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        # Extract imports defensively to avoid crashes on malformed or stripped binaries
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="ignore"))

        # PE section names are fixed‑length, null‑padded byte strings, so stripping nulls is necessary
        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        return {
            "file_type": "PE",
            "imports": imports,
            "sections": sections
        }

    except Exception:
        return {}
