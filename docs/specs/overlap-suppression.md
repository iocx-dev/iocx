# iocx Overlap Suppression Specification
**Version:** 1.0
**Status:** Stable
**Applies to:** IOCX Engine ≥ 0.4.0
**Last Updated:** 2026‑03‑27
**Maintainers:** MalX Labs

This document defines the deterministic rules IOCX uses to suppress overlapping IOC detections emitted by built‑in detectors and plugins. These rules ensure stable, predictable output without relying on semantic category priority.

## 1. Scope

This specification applies to:

• All IOCX detectors (built‑in and plugin‑based)
• All extraction modes (`extract`, `extract_from_text`, `extract_from_file`)
• All categories emitted by detectors

The suppression logic is implemented in the engine’s post‑processing stage and is category‑agnostic.

## 2. Definitions

### Match

A detection with:

• `value`: extracted IOC string
• `start`: inclusive character offset
• `end`: exclusive character offset
• `category`: detector‑assigned category

### Overlap

Two matches overlap if:

$$ [startA,endA)∩[startB,endB)≠∅ $$

### Containment

Match **B** is contained within **A** if:

$$ startA≤startBandendB≤endA $$

## 3. Sorting Rule (Pre‑Suppression)

Before suppression, IOCX sorts all matches by:

• Ascending start offset
• Descending length (`end - start`)

This ensures:

• Larger matches at the same start position come first
• Containing matches are evaluated before contained matches

This ordering is essential to the suppression behaviour.

## 4. Overlap Suppression Rules

### Rule 1 — No semantic priority

IOCX does **not** assign importance or specificity to categories. Suppression is based **only on offsets**, not on category meaning.

### Rule 2 — Contained match suppression

After sorting, IOCX iterates greedily:

• A match **survives** if `start >= last_end`
• Otherwise, it is **suppressed**

This means:

> If match B is fully inside match A, B is suppressed.

This is the core suppression rule.

### Rule 3 — Equal‑range suppression (important)

If two matches have identical `(start, end)` offsets:

• The **first** match in sorted order survives
• All others are **suppressed**, regardless of category

This matches the engine’s greedy interval‑selection logic.

### Rule 4 — Partial overlap

If two matches overlap but neither contains the other:

• The first match in sorted order survives
• The second is suppressed
• This is a side‑effect of the greedy algorithm, not semantic suppression

### Rule 5 — Intra‑category deduplication

After suppression:

• Values are deduplicated **per category**
• Deduplication is **order‑preserving**
• Case‑normalisation applies only to specific categories (`domains, emails, hashes`)

### Rule 6 — Ordering guarantee

Final IOC lists preserve:

• The order of **first surviving occurrence**
• Across categories, ordering is independent

## 5. Examples (Normative)

### URL contains domain

```
http://example.com example.com
```

• URL survives
• Domain suppressed

### URL contains IP

```
https://156.65.42.8/access.php
```

• URL survives
• IP suppressed

### Equal‑range matches

```
example.com
```

If both URL and domain detectors emit the same span:

• Only the first in sorted order survives

### Partial overlap

```
abc@example.com/path
```

• One match survives (greedy selection)
• No semantic priority applied

## 6. Guarantees

IOCX guarantees:

• Deterministic suppression
• Category‑agnostic behaviour
• No semantic priority
• Stable ordering
• No empty or whitespace‑padded values
