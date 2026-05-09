import pytest

from iocx.analysis.heuristics import analyse_pe_heuristics
from iocx.validators import run_structural_validators


def _find(dets, value, reason):
    for d in dets:
        if d.value == value and d.metadata.get("reason") == reason:
            return d
    return None


def build_analysis(sections=None, data_directories=None, extended=None, obfuscation=None):
    return {
        "sections": sections or [],
        "data_directories": data_directories or [],
        "extended": extended or [],
        "obfuscation": obfuscation or [],
    }


def test_packer_high_entropy_section():
    metadata = {
        "file_type": "PE",
        "imports": [],
        "import_details": [],
        "tls": {},
        "signatures": [],
        "has_signature": False,
    }

    analysis = build_analysis(
        sections=[
            {
                "name": ".text",
                "raw_size": 4096,
                "virtual_size": 4000,
                "characteristics": 0x60000020,
                "entropy": 8.2,
            }
        ]
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
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

    analysis = build_analysis(
        sections=[
            {
                "name": "UPX1",
                "raw_size": 2048,
                "virtual_size": 1800,
                "characteristics": 0x60000020,
                "entropy": 6.0,
            }
        ]
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
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

    analysis = build_analysis(
        sections=[{"name": ".text"}],
        extended=[
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
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
    dets = analyse_pe_heuristics(metadata, analysis)

    d = _find(dets, "pe_structure_anomaly", "callback_outside_tls_range")
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

    analysis = build_analysis(
        sections=[
            {
                "name": ".rwx",
                "raw_size": 1024,
                "virtual_size": 1000,
                "characteristics": 0xA0000020, # EXECUTE + WRITE
                "entropy": 5.0,
            }
        ]
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
    dets = analyse_pe_heuristics(metadata, analysis)

    assert _find(dets, "anti_debug_heuristic", "anti_debug_api_import")
    assert _find(dets, "anti_debug_heuristic", "timing_api_import")

    # RWX is structural
    assert _find(dets, "pe_structure_anomaly", "section_rwx")


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

    analysis = build_analysis(sections=[{"name": ".text"}])

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
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

    analysis = build_analysis(
        sections=[{"name": ".text"}],
        extended=[
            {
                "value": "header",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {"subsystem_human": "Windows GUI"},
            }
        ],
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
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

    analysis = build_analysis(sections=[{"name": ".text"}])

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
    dets = analyse_pe_heuristics(metadata, analysis)

    assert _find(dets, "pe_structure_anomaly", "signature_flag_set_but_no_metadata")


def test_synthetic_triggers_all_heuristics():
    metadata = {
        "file_type": "PE",
        "imports": ["KERNEL32.dll", "ntoskrnl.exe", "user32.dll"],
        "import_details": (
            [
                {"dll": "KERNEL32.dll", "function": "IsDebuggerPresent", "ordinal": None},
                {"dll": "KERNEL32.dll", "function": "GetTickCount", "ordinal": None},
                {"dll": "ntoskrnl.exe", "function": "KeBugCheckEx", "ordinal": None},
            ]
            + [{"dll": "user32.dll", "function": None, "ordinal": i} for i in range(600)]
        ),
        "tls": {},
        "signatures": [],
        "has_signature": True,
    }

    analysis = build_analysis(
        sections=[
            {
                "name": "UPX0",
                "raw_size": 4096,
                "virtual_size": 4000,
                "characteristics": 0xE0000020,
                "entropy": 8.6,
            },
            {
                "name": ".rwx",
                "raw_size": 2048,
                "virtual_size": 1800,
                "characteristics": 0xA0000020,
                "entropy": 5.0,
            },
        ],
        extended=[
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
            },
            {
                "value": "header",
                "start": 0,
                "end": 0,
                "category": "pe_metadata",
                "metadata": {"subsystem_human": "Windows GUI"},
            },
        ],
    )

    analysis["structural"] = run_structural_validators({}, metadata, analysis)
    dets = analyse_pe_heuristics(metadata, analysis)

    expected = {
        ("packer_suspected", "packer_section_name"),
        ("packer_suspected", "high_entropy_section"),
        ("anti_debug_heuristic", "anti_debug_api_import"),
        ("anti_debug_heuristic", "timing_api_import"),
        ("pe_structure_anomaly", "section_rwx"),
        ("pe_structure_anomaly", "callback_outside_tls_range"),
        ("import_anomaly", "large_import_table"),
        ("import_anomaly", "high_ordinal_import_ratio"),
        ("import_anomaly", "uncommon_dll_for_gui_subsystem"),
        ("pe_structure_anomaly", "signature_flag_set_but_no_metadata"),
    }

    seen = {(d.value, d.metadata.get("reason")) for d in dets}
    for pair in expected:
        assert pair in seen, f"Missing heuristic {pair}"
