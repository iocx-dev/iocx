# Methodology in Practice

This page describes the research methodology that underpins IOCX and the broader PE structural research conducted at MalX Labs. It is written for contributors to IOCX, technical evaluators of PAAX, and researchers who want to understand *how* IOCX is built, *why* its design choices look the way they do, and *what* methodological commitments back the artefacts it produces.

The full adversarial-PE taxonomy and commercial fixture suite are maintained separately at [paax.dev](https://paax.dev). This page covers the principles common to both.

---

## The problem

Most security tools treat the PE format as if its specification were a faithful description of how Windows actually handles binaries. It is not. Windows' loader is materially more permissive than the documented spec, and real-world binaries — packers, malware staging chains, custom loaders, and exploit-chain payloads, routinely exploit that permissiveness.

This produces a category of bug that is structurally invisible to most testing: **loader–tool divergence**. The binary loads correctly under Windows, but the analysis tool — disassembler, AV engine, sandbox, forensic parser — silently misinterprets, mishandles, or crashes on it.

These bugs are:

- Hard to find with conventional fuzzing, because random mutation rarely produces Windows-loader-valid output
- Hard to disclose with the precision vendor PSIRTs expect, because the failing sample usually carries multiple co-occurring anomalies and the responsible structural feature is not cleanly isolated
- Hard for vendors to fix, because the disclosure language inherits the ambiguity

The methodology described below is built to address all three problems.

---

## Principle 1: Construct, don't reduce

Conventional vulnerability research follows a *reduce* workflow: find a failing sample, minimise it, disclose the minimised form. This works for exploitability research but produces low-quality artefacts for parser-correctness work, because the minimised sample is still derived from an opaque starting point.

The methodology here inverts the workflow. **Samples are constructed from a known-clean PE base by deliberately introducing exactly one structural anomaly, documented at byte level before any tool is ever pointed at the sample.** The anomaly is reversible, the construction recipe is committed, and the resulting sample is hash-locked.

The consequence: when a tool fails on the sample, the responsible anomaly is, by construction, the one applied. There is no bisection problem. The disclosure language can be precise from the first email.

---

## Principle 2: Single-anomaly discipline

Each canonical fixture carries **exactly one isolated structural anomaly**. Multi-anomaly samples are not permitted as canonical evidence in this methodology.

This is the most consequential commitment in the methodology, and it shapes everything downstream:

- Disclosure language is precise: *"engine X fails on a sample carrying a single anomaly of type Z, located at offset N"* leaves vendors no room for scope arguments.
- Vendor PSIRT triage is faster: the responsible feature is named in the first email; no bisection is required on the vendor side.
- Methodology is reproducible: every fixture can be regenerated independently from its recipe, byte-identically.
- Findings are categorisable: each fixture has a single primary classification under the taxonomy, not a tuple of competing hypotheses.

For samples that violate this principle — in-the-wild artefacts, third-party samples, forensic case-work — a separate legacy bisection workflow exists. The output of any bisection that successfully isolates a single anomaly is then promoted to a fresh single-anomaly canonical fixture before disclosure proceeds.

---

## Principle 3: Windows is the ground truth

PE specification documents are not the ground truth. The PE specification describes what *should* load; Windows describes what *does* load. Where they differ, and they differ in many places, the methodology here treats **Windows behaviour as the correctness oracle**.

This is non-trivial. It means:

- A fixture that Windows refuses to map is not interesting for parser-divergence research, it's a true malformation, and any tool that also refuses is behaving correctly.
- A fixture that Windows happily maps but tools refuse to parse is the high-value class. This is where loader–tool divergence lives.
- A fixture that loads under data-mapping but not under executable mapping (or vice versa) is differentiated explicitly — Windows' loader behaviour varies by mode, and the methodology preserves that distinction.

The taxonomy maintained at [paax.dev](https://paax.dev) formalises these distinctions across five orthogonal classification axes.

---

## Principle 4: Determinism end-to-end

Every artefact in this methodology is deterministic. The fixture is byte-identical across regenerations. The classification taxonomy is fixed at fixture creation, not assigned ad hoc. The timing protocols produce medians over fixed run counts, with discard rules pre-committed.

This determinism is the same property that underpins [iocx](https://github.com/iocx-dev/iocx)'s output: any researcher running the same input through the same version of the tool gets the same output, on any platform, for years. Determinism is what makes the methodology *defensible* — under PSIRT review, under expert-witness scrutiny, and under independent replication.

---

## How this applies to IOCX specifically

IOCX applies these principles to **operation** rather than to fixture construction. Specifically:

- IOCX's PE structural extractors are correctness-validated against the same canonical fixtures the methodology produces.
- IOCX's output is deterministic by design: identical input produces identical output across versions, platforms, and runs.
- IOCX's parser corrections are driven by findings from the methodology, not by retro-fitting to malware samples.
- IOCX's schema is designed for downstream IOC and heuristic consumers (MISP, OpenCTI, custom pipelines) where reproducibility matters more than novelty.

The methodology is what IOCX is built *on*, not bolted onto.

---

## How this applies to the broader research programme

The full adversarial-PE corpus, the five-axis taxonomy, and the commercial fixture suite are maintained at [paax.dev](https://paax.dev). PAAX provides:

- Curated, deterministic adversarial PE fixtures across the corpus
- Cross-tool behavioural maps showing where Windows, Ghidra, IDA, Binary Ninja, r2, and proprietary loaders diverge
- Custom fixture design for vendors with proprietary loader code paths

IOCX is the open-source PE structural research tool. PAAX is the commercial fixture suite that backs the research programme. They share methodology and methodology only.

---

## Validation in the field

The public fixture corpus is frozen at 99 fixtures — the contract-test inputs developed during IOCX's initial release cycle, sufficient to validate the methodology and demonstrate it in practice. The public corpus is not extended publicly; subsequent fixture work is conducted under PAAX.

The methodology has produced disclosable findings in production tooling. Documented examples:

- **Ghidra 12.1 → 12.2** — A single-anomaly fixture targeting `SizeOfRawData` (classified `VRD-I + STI-A + LPM-3 + AIL-3` under the PAAX taxonomy) exposed an uncaught `IndexOutOfBoundsException` in Ghidra's PE importer. Disclosed via Ghidra's issue tracker, accepted by the maintainers, scheduled for the 12.2 milestone, fixed to align with Windows' data-mapping semantics. Full case study: [paax.dev/#case](https://paax.dev/#case).

Further findings will be documented here as disclosure windows close.

---

## Contributing

IOCX welcomes contributors who understand and accept these methodological commitments. If you're contributing parser fixes, your fix should be backed by a fixture that demonstrates the bug under single-anomaly discipline. If you're contributing new extractors, your extractor's output should be deterministic and schema-anchored.

The public fixture corpus is closed at 99 fixtures and is not extended through community contribution. New fixtures are developed under PAAX. Contributions to IOCX focus on the tool itself — parser improvements, schema extensions, integration support — not on the fixture corpus.

Issues and pull requests that propose **fixture contributions** inconsistent with these principles — fuzz-derived samples used as canonical fixtures, non-deterministic output from the fixture pipeline, or fixtures lacking taxonomy classification — will be redirected to discussion before merge. Tool-level fixes, bug reports, and parser improvements follow standard open-source contribution practice.

---

## Further reading

- **IOCX**: [github.com/iocx-dev/iocx](https://github.com/iocx-dev/iocx) — the tool
- **PAAX**: [paax.dev](https://paax.dev) — the adversarial PE taxonomy, case studies, and commercial fixture suite
- **PAAX Ghidra case study**: [paax.dev/#case](https://paax.dev/#case) — methodology applied to a real disclosure

---

*Methodology version 1.0. Developed at MalX Labs] by Peter Weaver. Last reviewed: 2026-06-21.*
