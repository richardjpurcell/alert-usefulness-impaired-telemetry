# D08 — Bounded discrimination validation (locked design)

**Purpose.** Test the narrow diagnostic claim that three-valued, claim-conditioned reconstruction distinguishes a complete nonmatching audit unit from one that cannot be evaluated because the retained attributes are insufficient. This is an **evaluation of evidence reconstruction under controlled representation changes**, not an independent assessment of malicious activity or alert usefulness.

## Lock and provenance

D08 uses the previously frozen D03 source inventory, D07.1 preflight archive hashes, D06 P0–P3 encoders and D06/D07 decoders without changing their implementation. Input records are selected by **one-based original source line**. All source-record claims are evaluated against the original, unmodified structured fields, not against impaired projections. All D07 records with a source UTC timestamp are eligible; unknown-time records are never given fabricated times.

The 24 cases are **predeclared** in `configs/d08_claim_unit_cases.json` before running the D08 evaluation on the actual second archive. Synthetic development checks are non-blind and were used to test the software contract; this is not a preregistered independent assessment. Each case fixes the source line(s), claim, representation policy, optional field-removal intervention, whether the complete source unit has a claim witness, and the expected three-valued answer. Source witnesses were identified in prior D03/D07 record inspection; the present study is not independently blind and does not have analyst-adjudicated incident labels. Do not change a case or its expected status to achieve agreement; record deviations instead.

## Case strata

Twelve cases come from OTRF Empire Mimikatz (D03) and twelve from OTRF Comsvcs MiniDump (D07), using *the same two scenarios already used to construct the audit*. Cases include:

1. Original raw witnesses (a structured LSASS access and the Comsvcs process-creation invocation).
2. Original raw nonwitnesses, including a non-LSASS access and an image load.
3. Count-only P1 representations that retain an event count but not attributes required by the claim.
4. Joint-field P2, and PID-enriched P3 representations that selectively retain or discard requirements.
5. Explicitly **synthetic field withholding** from an otherwise real source witness (removing `SourceImage` before an unchanged P2 encoder). This tests a controlled representation failure, not an observed SOC collection failure.
6. A **real two-record group** from Mimikatz (source lines 288 and 818, both from WORKSTATION5 within one five-second UTC window) where one event contains a PowerShell source accessing a *non-LSASS* target and another contains a non-PowerShell source accessing LSASS. The joint signature must not invent a PowerShell-to-LSASS relationship.

The last two types are intentional stress cases, not untouched natural traces. No threat-detection accuracy claim follows from the results.

## Evaluation contracts and baselines

- `source_witness`: Is at least one complete original source record in the unit a witness to the declared event predicate? **True/false is not incident ground truth**.
- `reconstructed`: `supported`, `unsupported` **within the evaluated unit**, or `indeterminate` from the **serialized** representation. No decoder accesses the original source during reconstruction.
- A correct `unsupported` outcome means a sufficiently complete representation of the *unit* excludes the declared event pattern. It does **not** mean the attack did not occur elsewhere.
- A correct `indeterminate` outcome is appropriate where necessary attributes or relationships have been discarded.
- **Baseline E (membership-only):** number of original records represented by the encoded unit, irrespective of retained attributes. All case conditions retain their selected source-record membership; this baseline cannot discriminate the three outcomes.
- **Baseline B (two-valued):** the same decoder with `indeterminate` collapsed into `not supported`. This is explicitly a *lossy presentation baseline*, not a published detector or an implementation of Michael et al. (2020).

Output includes a case-by-case report, three-valued agreement against the predeclared expectations, source-witness confusion, false support, false exclusion (unsupported despite an original witness), abstentions for present/absent witnesses, and binary-baseline missing-evidence false exclusions. Report payload bytes separately; **serialized bytes are not operational storage or processing costs**.

## Decision rule (stated before execution)

**Limited positive evidence:** all predeclared outcomes match, false support/exclusion are zero, and at least one true-source witness becomes indeterminate after attributes are discarded while a complete nonmatching unit is correctly unsupported; this shows a *diagnostic distinction* hidden by B/E. Do **not** infer novel research contribution from this success alone; the cases are purposefully selected.

**Negative/inconclusive:** unexpected statuses, fabricated support, false exclusion, or no demonstrated distinction between incomplete and fully evaluable nonmatching units. Preserve and report the failures rather than retuning policy encoders or reference labels.

**Novelty gate:** even a perfect score establishes implementation correctness and bounded diagnostic expressivity, **not independent empirical validation** or methodological novelty against forensic-validity and question-answerability research. The manuscript must disclose that limitation; reconsider JISA suitability if the paper's main claimed advance relies on D08 alone.

## Execution and controls

Use repository root; the two source ZIPs must be present in `data/raw/mordor/`. Validate D03/D07 source hashes before decoding. Run `python scripts/run_d08_claim_discrimination.py` then `PYTHONPATH=src:. python -m pytest -q`. Outputs are saved to `outputs/d08_claim_discrimination/` with a manifest of code, cases, input archives, checksums, and results. Do not edit D03–D07 outputs, encoders, or decoders.
