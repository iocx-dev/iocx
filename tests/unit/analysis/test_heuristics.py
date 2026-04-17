import pytest
from iocx.analysis.heuristics import analyse_pe_heuristics, _analyse_tls
from iocx.models import Detection


def _find(dets, value, reason):
    for d in dets:
        if d.value == value and d.metadata.get("reason") == reason:
            return d
    return None


def test_packer_high_entropy_section():
    metadata = {
        "file_type": "PE",
        "imports": [],
        "import_details": [],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {
        "sections": [
            {
                "name": ".text",
                "raw_size": 4096,
                "virtual_size": 4000,
                "characteristics": 0x60000020,
                "entropy": 8.2,
            }
        ],
        "obfuscation": [],
        "extended": [],
    }

    dets = analyse_pe_heuristics(metadata, analysis)
    d = _find(dets, "packer_suspected", "high_entropy_section")

    assert d is not None
    assert d.metadata["section"] == ".text"
    assert d.metadata["entropy"] == 8.2


def test_packer_upx_section_name():
    metadata = {
        "file_type": "PE",
        "imports": [],
        "import_details": [],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {
        "sections": [
            {
                "name": "UPX1",
                "raw_size": 2048,
                "virtual_size": 1800,
                "characteristics": 0x60000020,
                "entropy": 6.0,
            }
        ],
        "obfuscation": [],
        "extended": [],
    }

    dets = analyse_pe_heuristics(metadata, analysis)
    d = _find(dets, "packer_suspected", "packer_section_name")

    assert d is not None
    assert d.metadata["section"] == "UPX1"


def test_tls_callback_outside_range():
    metadata = {
        "file_type": "PE",
        "imports": [],
        "import_details": [],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {
        "sections": [],
        "obfuscation": [],
        "extended": [
            {
                "value": "tls_directory",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {
                    "start_address": 0x1000,
                    "end_address": 0x2000,
                    "callbacks": 0x3000,
                },
            }
        ],
    }

    dets = analyse_pe_heuristics(metadata, analysis)
    d = _find(dets, "tls_callback_anomaly", "callback_outside_tls_range")

    assert d is not None
    assert d.metadata["callbacks"] == 0x3000


def test_anti_debug_imports_and_rwx_section():
    metadata = {
        "file_type": "PE",
        "imports": ["KERNEL32.dll"],
        "import_details": [
            {"dll": "KERNEL32.dll", "function": "IsDebuggerPresent", "ordinal": None},
            {"dll": "KERNEL32.dll", "function": "GetTickCount", "ordinal": None},
        ],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {
        "sections": [
            {
                "name": ".rwx",
                "raw_size": 1024,
                "virtual_size": 1000,
                "characteristics": 0xA0000020, # EXECUTE + WRITE
                "entropy": 5.0,
            }
        ],
        "obfuscation": [],
        "extended": [],
    }

    dets = analyse_pe_heuristics(metadata, analysis)

    assert _find(dets, "anti_debug_heuristic", "anti_debug_api_import")
    assert _find(dets, "anti_debug_heuristic", "timing_api_import")
    assert _find(dets, "anti_debug_heuristic", "rwx_section")


def test_import_anomalies_large_and_ordinal_ratio():
    import_details = []
    for i in range(600):
        import_details.append(
            {
                "dll": "kernel32.dll",
                "function": None if i < 400 else f"Func{i}",
                "ordinal": i if i < 400 else None,
            }
        )

    metadata = {
        "file_type": "PE",
        "imports": ["kernel32.dll"],
        "import_details": import_details,
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {"sections": [], "obfuscation": [], "extended": []}

    dets = analyse_pe_heuristics(metadata, analysis)

    assert _find(dets, "import_anomaly", "large_import_table")
    assert _find(dets, "import_anomaly", "high_ordinal_import_ratio")


def test_import_anomaly_uncommon_dll_for_gui():
    metadata = {
        "file_type": "PE",
        "imports": ["ntoskrnl.exe"],
        "import_details": [
            {"dll": "ntoskrnl.exe", "function": "KeBugCheckEx", "ordinal": None}
        ],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = {
        "sections": [],
        "obfuscation": [],
        "extended": [
            {
                "value": "header",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {"subsystem_human": "Windows GUI"},
            }
        ],
    }

    dets = analyse_pe_heuristics(metadata, analysis)
    d = _find(dets, "import_anomaly", "uncommon_dll_for_gui_subsystem")

    assert d is not None
    assert d.metadata["dll"] == "ntoskrnl.exe"


def test_signature_flag_without_metadata():
    metadata = {
        "file_type": "PE",
        "imports": [],
        "import_details": [],
        "tls": {},
        "signatures": [],
        "has_signature": True,
    }

    analysis = {"sections": [], "obfuscation": [], "extended": []}

    dets = analyse_pe_heuristics(metadata, analysis)
    d = _find(dets, "signature_anomaly", "signature_flag_set_but_no_metadata")

    assert d is not None


def test_synthetic_triggers_all_heuristics():
    metadata = {
        "file_type": "PE",
        "imports": ["KERNEL32.dll", "ntoskrnl.exe", "user32.dll"],
        "import_details": (
            [
                # Anti-debug + timing
                {"dll": "KERNEL32.dll", "function": "IsDebuggerPresent", "ordinal": None},
                {"dll": "KERNEL32.dll", "function": "GetTickCount", "ordinal": None},
                # Uncommon DLL for GUI subsystem
                {"dll": "ntoskrnl.exe", "function": "KeBugCheckEx", "ordinal": None},
            ]
            + [
                # Lots of ordinal-only imports to trigger large table + high ordinal ratio
                {"dll": "user32.dll", "function": None, "ordinal": i}
                for i in range(600)
            ]
        ),
        "tls": {},
        "signatures": [],
        "has_signature": True, # triggers signature_anomaly
    }

    analysis = {
        "sections": [
            {
                # Triggers packer_section_name + high_entropy_section
                "name": "UPX0",
                "raw_size": 4096,
                "virtual_size": 4000,
                "characteristics": 0xE0000020, # EXECUTE | READ | WRITE
                "entropy": 8.6,
            },
            {
                # Triggers rwx_section
                "name": ".rwx",
                "raw_size": 2048,
                "virtual_size": 1800,
                "characteristics": 0xA0000020, # EXECUTE | WRITE
                "entropy": 5.0,
            },
        ],
        "obfuscation": [],
        "extended": [
            {
                # Triggers tls_callback_anomaly
                "value": "tls_directory",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {
                    "start_address": 0x1000,
                    "end_address": 0x2000,
                    "callbacks": 0x3000, # outside range
                },
            },
            {
                # Triggers uncommon_dll_for_gui_subsystem
                "value": "header",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {
                    "subsystem_human": "Windows GUI",
                },
            },
        ],
    }

    dets = analyse_pe_heuristics(metadata, analysis)

    expected = {
        ("packer_suspected", "packer_section_name"),
        ("packer_suspected", "high_entropy_section"),
        ("anti_debug_heuristic", "anti_debug_api_import"),
        ("anti_debug_heuristic", "timing_api_import"),
        ("anti_debug_heuristic", "rwx_section"),
        ("tls_callback_anomaly", "callback_outside_tls_range"),
        ("import_anomaly", "large_import_table"),
        ("import_anomaly", "high_ordinal_import_ratio"),
        ("import_anomaly", "uncommon_dll_for_gui_subsystem"),
        ("signature_anomaly", "signature_flag_set_but_no_metadata"),
    }

    seen = {(d.value, d.metadata.get("reason")) for d in dets}
    for pair in expected:
        assert pair in seen, f"Missing heuristic {pair}"


def test_tls_analysis_skips_incomplete_entries():
    analysis = {
        "extended": [
            {
                "value": "tls_directory",
                "metadata": {
                    # Missing start_address, end_address, callbacks
                    # This forces the `continue` branch
                }
            }
        ]
    }

    detections = _analyse_tls({}, analysis)

    # No detections should be produced
    assert detections == []
