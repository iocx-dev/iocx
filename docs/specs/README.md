# IOCX Specifications

This directory contains formal behavioural specifications for the IOCX engine.
These documents define **guaranteed contracts** that all detectors, plugins, and engine components must follow.

Specifications in this folder are:

- **Authoritative** — they describe how the engine *must* behave.
- **Versioned** — changes to these documents correspond to engine behaviour changes.
- **Stable** — once published, specs remain backwards‑compatible unless explicitly version‑bumped.
- **Developer‑focused** — intended for contributors, plugin authors, and maintainers.

---

## Available Specifications

### 1. `overlap-suppression.md`

Defines the deterministic rules IOCX uses to suppress overlapping IOC detections based solely on character offsets.

This includes:

- sorting rules
- containment suppression
- equal‑range suppression
- partial overlap behaviour
- category‑agnostic logic
- ordering guarantees

This spec is essential reading for anyone implementing detectors or writing plugins that emit positional matches.

### 2. `plugin-authoring-guidelines.md`

Defines the rules, expectations, and best practices for writing IOCX plugins.

---

## Purpose of the Specs Folder

The `specs/` directory exists to:

- document engine behaviour that must remain stable
- provide a reference for contributors
- prevent accidental regressions
- ensure plugin authors understand the engine’s expectations
- serve as a source of truth for test design

If you are contributing to IOCX or building plugins, start here.

---

## Contributing to Specifications

If you propose changes to engine behaviour:

1. Update the relevant spec file
2. Increment the spec version header
3. Add or update tests in `tests/` to enforce the new behaviour
4. Reference the spec change in your pull request

Specs and tests must always evolve together.

---

## Contact

For questions or proposals related to specifications, open a GitHub Discussion or submit a PR with a draft change.
