# IOCX Plugin Authoring Guidelines
**Version:** 1.0
**Status:** Stable
**Applies to:** IOCX Engine ≥ 0.4.0
**Last Updated:** 2026‑03‑27
**Maintainers:** MalX Labs

This document defines the rules, expectations, and best practices for writing IOCX plugins.
Plugins extend IOCX with custom detectors, transformers, and extraction logic while preserving the engine’s deterministic behaviour.

---

# 1. Overview

IOCX supports two plugin types:

1. **Transformers**
   - Modify or normalize the input text before detection
   - Run *before* all built‑in detectors
   - Useful for decoding, cleanup, or pre‑processing

2. **Detectors**
   - Emit IOC detections
   - Run *after* transformers and built‑in detectors
   - Useful for adding new IOC categories or custom patterns

3. **Enrichers**
   - Add context, scoring, or intelligence to detections produced by the engine or other plugins
   - Run *after* plugin detectors and built-in detectors

Plugins are loaded automatically at runtime from the plugin registry.

---

# 2. Plugin Structure

A plugin is a Python module that exposes:

- A `metadata` object
- A `transform(text, ctx)` function **or** a `detect(text, ctx)` function
- Optional helper functions or state

Example skeleton:

```python
from iocx.models import Detection, PluginMetadata

metadata = PluginMetadata(
    id="my.custom.detector",
    description="Detects custom internal indicators",
    version="1.0.0",
)

def detect(text, ctx):
    results = []
    # produce Detection(value, start, end, category)
    return results
```

# 3. Plugin Metadata Requirements

Each plugin must define a `PluginMetadata` instance with:

- Field Required Description
- id Yes Unique identifier for the plugin
- description Yes Human‑readable summary
- version Yes Plugin version string
- author No Optional attribution
- url No Optional documentation link


**Plugin IDs must be globally unique.**

Recommended format:

```
vendor.category.name
```

Examples:

- `malx.crypto.xmr`
- `internal.detectors.ticket-id`
- `acme.transformers.deobfuscate`

---

# 4. Transformer Plugins

Transformers modify the raw text before detection.

## Rules

- Must expose a `transform(text, ctx)` function
- Must return a string
- Must not return None
- Must not raise exceptions (catch internally and log via ctx.logger)
- Must be pure (no side effects outside the text)

## Use cases

- Base64 decoding
- De‑obfuscation
- Log normalization
- Removing null bytes from binary strings
- Extracting embedded text blocks

## Example

```python
def transform(text, ctx):
    try:
        return text.replace("\x00", "")
    except Exception as e:
        ctx.logger.warning(f"transform failed: {e}")
        return text
```

# 5. Detector Plugins

Detectors emit IOC matches.

## Rules

- Must expose a `detect(text, ctx)` function
- Must return a list of:
    - `Detection` objects, or
    - `(value, start, end, category)` tuples
- Must not raise exceptions
- Must not mutate the input text
- Must emit absolute character offsets into the provided text
- Must ensure `start < end` and both are valid indices

## Categories

Detectors may emit:

- Existing categories (`urls, ips, domains`, etc.)
- Custom categories (e.g., `internal.ticket`, `crypto.xmr`)

Custom categories will appear in the final JSON output automatically.

## Example
```python
import re
from iocx.models import Detection

pattern = re.compile(r"TICKET-[0-9]{6}")

def detect(text, ctx):
    results = []
    for m in pattern.finditer(text):
        results.append(
            Detection(
                value=m.group(0),
                start=m.start(),
                end=m.end(),
                category="internal.ticket"
            )
        )
    return results
```

# 6. Enricher Plugins

## 6.1 Purpose

Enrichers are used to:

- Score detections (e.g., suspicious registry keys)
- Add rationale or flags to detections
- Annotate IOCs with metadata (e.g., ASN info, PE heuristics)
- Produce structured enrichment for downstream analysis
- Populate ctx.metadata with enrichment context
- Enrichers must not perform detection or extraction.

## 6.2 Enricher Structure

An enricher plugin must:

- Inherit from IOCXPlugin
- Provide a metadata object
- Implement an enrich(text, ctx) method

Example skeleton:

```python
from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata

class Plugin(IOCXPlugin):
    metadata = PluginMetadata(
        id="vendor.enrich.example",
        name="Example Enricher",
        version="1.0.0",
        description="Adds enrichment to detections",
    )

    def enrich(self, text, ctx):
        # read ctx.detections
        # write to ctx.metadata
        pass
```

## 6.3 Enricher Responsibilities

Enrichers may:

- Read from ctx.detections
- Read from ctx.raw_text
- Write structured enrichment into ctx.metadata
- Add metadata to individual Detection objects

Enrichers must not:

- Modify ctx.raw_text
- Modify detection offsets
- Add or remove detections
- Perform network calls
- Raise exceptions (must log and continue)

## 6.4 Writing Enrichment

Enrichers write output exclusively to:

```python
ctx.metadata
```

This is the canonical enrichment store.

Example:

```python
ctx.metadata.setdefault("registry.keys", []).append({
    "value": det.value,
    "score": score,
    "reasons": reasons,
    "flags": flags,
})
```

Enrichment must be:

- Structured (dicts, lists)
- Deterministic
- Serializable to JSON
- Human‑readable and machine‑readable

# 6.5 Detection‑Level Metadata

Enrichers may also annotate individual detections:

```python
det.metadata["score"] = score
det.metadata["flags"] = flags
```

This metadata is internal and not shown in the CLI unless the enricher also writes to `ctx.metadata`.

# 6.6 When to Use Enrichment

Enrichment should be used only for:

- Custom plugin logic
- Scoring or classification
- Contextual intelligence
- Analysis‑ready metadata

Base detectors must not produce enrichment.

This preserves the engine’s separation of concerns:

- Detectors → produce IOCs
- Enrichers → add intelligence
- Analysis → builds on enrichment

# 6.7 Rationale & Verbosity

Enrichers are encouraged to provide verbose rationale explaining why a score or flag was assigned.

Example:

```json
{
  "value": "HKCU\\...\\Run\\BadApp",
  "score": 50,
  "reasons": [
    "Registry path contains persistence location: HKCU/HKLM Run key",
    "Matched suspicious substring: 'run'"
  ],
  "flags": {
    "persistence": true,
    "suspicious_substrings": ["run"]
  }
}
```

This improves analyst understanding and supports downstream automation.

# 6.8 Performance Expectations

Enrichers should:

- Avoid scanning the entire text repeatedly
- Prefer operating on ctx.detections rather than raw text
- Avoid expensive operations on large files
- Keep enrichment lightweight and deterministic

# 6.9 Testing Enrichers

Tests should verify:

- Correct enrichment output
- Deterministic scoring
- No modification of detections
- No exceptions raised
- JSON‑serializable output
- Correct behaviour on empty detection sets

# 7. Overlap Suppression & Ordering

Plugins must understand IOCX’s deterministic suppression rules:

- Matches are sorted by `(start, -length)`
- Greedy interval selection keeps the first match and suppresses overlaps
- Equal‑range matches: only the first survives
- Category does **not** affect suppression
- Custom categories follow the same rules as built‑ins

See `overlap-suppression.md` for the full formal specification.

# 8. Normalisation Rules

After suppression, IOCX normalizes values:

- `domains, emails, hashes` → lowercased
- Leading/trailing whitespace removed
- Duplicate values removed per category (order‑preserving)

Plugins should avoid performing their own normalization unless necessary.

# 9. Logging & Error Handling

Plugins must:

- Catch all exceptions
- Log via ctx.logger
- Never raise errors to the engine
- Fail gracefully and return an empty list or unchanged text

## Example:

```python
try:
    ...
except Exception as e:
    ctx.logger.warning(f"[iocx] plugin {metadata.id} failed: {e}")
    return []
```

# 10. Performance Guidelines

Plugins should:

- Avoid O(n²) operations on large text blobs
- Prefer compiled regexes
- Avoid excessive allocations
- Avoid scanning the entire text multiple times
- Use streaming or chunking for very large inputs (if applicable)

IOCX is optimized for ~200 MB/s throughput; plugins should not degrade this significantly.

# 11. Testing Plugins

Recommended tests:

- Correct detection of expected patterns
- Correct handling of malformed input
- No exceptions raised
- Correct offset calculation
- Behaviour under overlap suppression
- Performance on large samples

Plugins should include a minimal test suite in the host project.

# 12. Plugin Distribution

Plugins may be:

- Bundled with IOCX
- Distributed as separate Python packages
- Loaded dynamically via the plugin loader

Recommended naming convention for external packages:

```Code
iocx-plugin-<name>
```

# 13. Security Considerations

Plugins must:

- Never execute untrusted code
- Never evaluate user‑provided expressions
- Never perform network calls without explicit user intent
- Treat all input as hostile
- Avoid unsafe parsing libraries

IOCX is a **static‑only** engine; plugins must preserve this guarantee.

# 14. Summary

Plugins extend IOCX safely and predictably by following these rules:

- Transformers modify text
- Detectors emit structured matches
- Enrichers do not create new detections and do not modify the input text
- Offsets must be accurate
- Errors must be contained
- Behaviour must remain deterministic
- Categories may be custom
- Suppression rules always apply

For questions or proposals, open a GitHub Discussion or submit a PR with a draft plugin.
