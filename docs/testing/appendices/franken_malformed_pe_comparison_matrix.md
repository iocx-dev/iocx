# Appendix 3.5.1 – Franken Malformed PE (PE32 vs PE32+) Comparison Matrix

A consolidated behavioural matrix comparing IOCX’s handling of the **Franken malformed PE32** and **Franken malformed PE32+** fixtures.
Both binaries deliberately introduce *multi‑vector structural corruption*, including overlapping sections, misaligned raw data, contradictory optional‑header fields, invalid directory RVAs, and unmappable entrypoints.

This appendix ensures that IOCX’s PE32 and PE32+ parsing paths behave **consistently where appropriate and independently where required**, while maintaining deterministic, JSON‑safe behaviour.

# Purpose

To validate that IOCX:

- applies **architecture‑specific parsing rules** correctly
- surfaces **all relevant structural anomalies**
- parses valid sections even when surrounded by corruption
- avoids false-positives in IOC extraction
- remains **stable** under extreme malformed conditions
- produces **consistent** metadata across architectures

The Franken fixtures represent the **maximum‑stress adversarial cases** for v0.7.1.

# Combined Franken Matrix (PE32 vs PE32+)

| Behaviour / Anomaly                            | **PE32 Franken**                               | **PE32+ Franken**                             | Notes                                         |
|------------------------------------------------|------------------------------------------------|-----------------------------------------------|-----------------------------------------------|
| **Valid sections parsed**                      | ✔ ``.text``, ``.rdata``, ``.data``, ``.rsrc`` | ✔ ``.text``, ``.rdata``, ``.data``, ``.rsrc`` | Both fixtures contain valid section headers   |
| **Section overlap detected**                   | ✔                                             | ✔                                             | ``.text`` ↔ ``.rdata`` overlap in both        |
| **Raw misalignment detected**                  | ✔ ``.rdata``, ``.data``                       | ✔ ``.rdata``, ``.data``                       | Both detect identical misalignment patterns   |
| **Optional header inconsistent size**          | ✔                                             | ✔                                             | ``SizeOfImage ``< ``max_section_end`` in both |
| **Entrypoint out of bounds**                   | ✔                                             | ✔                                             | EP RVA = 0x3000 unmapped in both              |
| **Data directory out of range**                | ✔                                             | ✔                                             | Import directory RVA > SizeOfImage            |
| **Zero‑RVA non‑zero directory**                | ✔                                             | ✔                                             | Resource directory malformed in both          |
| **Import RVA invalid**                         | ✔                                             | ✔                                             | Same invalid import RVA in both               |
| **Obfuscation hint: abnormal section overlap** | ✔                                             | ✔                                             | Both emit the hint                            |
| **Entropy computed**                           | ✔                                             | ✔                                             | All four sections analysed in both            |
| **Imports / resources / exports**              | ✘ none                                        | ✘ none                                         | Expected                                      |
| **Rich header**                                | ✘ none                                        | ✘ none                                         | Expected                                      |
| **Signature metadata**                         | ✘ none                                        | ✘ none                                         | Expected                                      |
| **IOC extraction**                             | ✘ no false positives                          | ✘ no false positives                           | Expected                                      |
| **Architecture‑specific header parsing**       | ✔ x86                                         | ✔ AMD64                                       | Both parse correctly                          |

# Interpretation

## PE32 Franken

- Exercises the *full anomaly surface*.
- All four sections are parsed and analysed.
- Triggers **every** structural heuristic: overlap, misalignment, invalid EP, invalid directories, inconsistent sizes.
- Demonstrates IOCX’s ability to parse valid structures while rejecting invalid ones.

## PE32+ Franken

- Mirrors the PE32 anomaly pattern exactly.
- All four sections are parsed and analysed.
- Triggers the same anomaly set as PE32.
- Confirms that PE32+ parsing is equally robust under multi-vector corruption.

# Contract enforced

Across both fixtures, IOCX must:

## Always detect

- `section_overlap`
- `section_raw_misaligned`
- `optional_header_inconsistent_size`
- `entrypoint_out_of_bounds`
- `data_directory_out_of_range`
- `data_directory_zero_rva_nonzero_size`
- `import_rva_invalid`

## Always produce
- Four parsed sections
- Valid entropy for each section
- No imports, resources, exports, TLS, or signatures
- No IOC false-positives
- One obfuscation hint: `abnormal_section_overlap`

## Always remain

- deterministic
- JSON‑safe
- architecture‑correct
- non‑hallucinatory
