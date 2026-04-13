# IOCX PE Analysis Pipeline

IOCX includes a deterministic, static, offline analysis pipeline for Portable Executable (PE) files.
The pipeline is designed to safely process untrusted binaries without executing them, unpacking them, or performing any dynamic analysis. All stages operate on raw bytes only and are fully deterministic.

This document describes the PE pipeline as implemented in v0.6.0, including:

- file-type detection
- PE parsing
- unified core metadata extraction
- string extraction
- obfuscation heuristics
- IOC detection
- output assembly

It also outlines how future versions (v0.7.0+) will extend this pipeline with behavioural heuristics.

## 1. Pipeline Overview

The PE analysis pipeline runs through the following ordered stages:

- File Type Detection
- PE Parsing
- Unified Core Metadata Extraction (v0.6.0)
- String Extraction
- Obfuscation Heuristics (v0.5.0)
- Unified Core Metadata Summary (v0.6.0)
- IOC Detection
- Output Assembly

Each stage is offline, deterministic, and safe to run on malicious or malformed binaries.

```mermaid
flowchart TD

    subgraph Input
        F[Untrusted File]
    end

    subgraph Stage1_FileType
        MAGIC[File Type Detection]
    end

    subgraph Stage2_PEParsing
        PE[PE Parser]
    end

    subgraph Stage3_Core
        CORE[Unified Core Metadata Extraction<br/>(Headers, Sections, Imports, Exports,<br/>Resources, TLS, Signatures)]
    end

    subgraph Stage4_Strings
        STR[String Extraction]
    end

    subgraph Stage5_Obfuscation
        OBF[Obfuscation Heuristics (v0.5.0)]
    end

    subgraph Stage6_IOC
        DET[IOC Detectors]
    end

    subgraph Output
        OUT[JSON Output]
    end

    F --> MAGIC
    MAGIC --> PE

    PE --> CORE
    PE --> STR

    CORE --> OBF
    STR --> OBF

    CORE --> DET
    STR --> DET
    OBF --> DET

    DET --> OUT
```

## 2. File Type Detection

IOCX uses signature‑based identification to determine whether a file is a PE. This step is structural only, non‑heuristic, and non‑executing. If the file is not a PE, the PE pipeline is skipped.

## 3. PE Parsing

IOCX parses the binary using a defensive, read-only approach. The parser extracts:

- DOS header
- NT headers
- Optional header
- Section table
- Data directory pointers

All parsing is wrapped in exception handling to avoid crashes on malformed samples. No dynamic loading or execution occurs.

## 4. Unified Core Metadata Extraction (v0.6.0)

In v0.6.0, IOCX extracts all structural PE metadata in a single unified stage.

The unified core includes:

### Header

- entry point
- image base
- subsytem
- timestamp
- machine type
- characteristics flags

### Optional Header

- section alignment
- file alignment
- size of image
- size of headers
- linker version
- OS version
- subsystem version

### Import Table

- DLL names
- Imported functions
- ordinals
- delayed imports
- bound imports

### Export Table

- exported names
- ordinals
- forwarded exports

### Resource directory

- resource types
- resource sizes
- entropy
- language codes
- extracted resource strings

### TLS Directory

- start address
- end address
- callback table pointer

### Digital Signature Presence

- boolean `has_signature`
- raw signature metadata

### Sections (*in standard, deep, and full analysis modes only*)

- section name
- raw size
- virtual size
- characteristics
- entropy

### Extended Metadata summary (*in full analysis mode only*)

- summary data across all metadata categories
- resource entropy min, max and average.

All extracted metadata is descriptive only. No scoring, heuristics, or behavioural interpretation occurs in v0.6.0.

## 5. String Extraction

IOCX extracts printable ASCII and UTF‑16LE strings from:

- `.text`
- `.rdata`
- `.data`
- entire file (fallback)

Extracted strings feed into:

- IOC detection
- obfuscation heuristics
- resource string extraction

Extraction is deterministic and bounded.

## 6. Obfuscation Heuristics (v0.5.0)

This module provides lightweight static hints about potential packing or obfuscation.

> Obfuscation heuristics are only included when deep or full analysis is enabled. It is not included in standard analysis mode.

Heuristics include:

- suspicious section names (`.upx`, `.aspack`, `.mpress`, etc.)
- high‑entropy sections
- abnormal section layout
- simple string‑obfuscation patterns

Each heuristic emits a structured detection object. These hints are contextual, not behavioural.

## 7. IOC Detection

After metadata and string extraction, IOCX runs its IOC detectors across:

- raw bytes
- extracted strings
- resource strings
- metadata fields

Detectors identify:

- file paths
- URLs
- domains
- IP addresses
- hashes
- email addresses
- cryptographic constants

Detection is static and deterministic.

## 8. Output Assembly

The engine merges:

- unified core metadata
- obfuscation hints
- extended metadata summary
- IOC detections

into a single structured JSON document, including:

- `file`
- `type`
- `iocs.*`
- `metadata.file_type`
- `metadata.imports`
- `metadata.sections`
- `metadata.resources`
- `metadata.resource_strings`
- `metadata.import_details`
- `metadata.delayed_imports`
- `metadata.bound_imports`
- `metadata.exports`
- `metadata.tls`
- `metadata.header`
- `metadata.optional_header`
- `metadata.rich_header`
- `metadata.signatures`
- `metadata.has_signature`
- `analysis.*`

No network access or external lookups occur.

## 9. Security Model

The PE pipeline is designed for safe analysis of untrusted input:

- no execution
- no unpacking
- no emulation
- no dynamic imports
- no network calls
- no ML/AI models
- deterministic, offline processing

All analysis is read-only.

## 11. Roadmap Alignment

### v0.5.0 — Obfuscation Heuristics

- section names
- entropy
- layout anomalies
- string obfuscation

### v0.6.0 — Unified Core Metadata (this version)

- headers
- sections
- imports
- exports
- resources
- TLS directory
- signature presence

### v0.7.0 — Behavioural Heuristics (future)

- packer detection
- TLS callback heuristics
- anti‑debug heuristics
- import anomaly scoring
- signature anomalies
- control‑flow hints

v0.6.0 provides the structural foundation for v0.7.0.

## 12. Summary

The IOCX PE pipeline in v0.6.0 is static, deterministic, offline, safe, modular, and extensible. It significantly expands IOCX’s visibility into PE structure while preserving its core philosophy: no dynamic analysis, no risk, no surprises.
