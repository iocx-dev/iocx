import pefile

def parse_pe(path):
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="ignore"))

        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        return {
            "file_type": "PE",
            "imports": imports,
            "sections": sections
        }

    except Exception:
        return {}
