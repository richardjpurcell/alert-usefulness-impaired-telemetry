# D08 — Three-valued claim-discrimination protocol and interpretation

**Status:** Implementation and 24 predeclared cases; full actual-source results must be reproduced locally with both OTRF ZIP archives. The published repository D03–D07 files are left unchanged.

## Narrow question

When the original evidence for a claim exists (or is absent within a unit), can a decoder operating *only on retained fields* correctly distinguish supported evidence, evaluable unit-local non-support, and indeterminacy due to missing fields?

The case specification is in `configs/d08_claim_unit_cases.json`, locked with the design in `docs/design/d08_trivalent_discrimination_validation.md`. D08 directly imports the unchanged D06 encoder and D06/D07 decoders. It validates D03's full source and D07's archive checksum/preflight before processing cases. Two cases deliberately withhold `SourceImage` before passing a record to the frozen encoder. Such modification is a controlled projection, **not an observed information-flow failure**.

## Comparison boundaries

- **Three-valued:** `supported`, `unsupported`, or `indeterminate` (unit-local, *not* a verdict about the complete incident).
- **Source reference:** Boolean membership of each unit in the predeclared original-field witness predicate, not independently adjudicated attack ground truth.
- **Two-valued comparator:** `supported` versus `not supported` (collapses `unsupported` and `indeterminate`); it is a lossy baseline, not a reproduced research system.
- **Membership comparator:** counts retained original source records without regard to retained attributes. All 24 cases preserve their declared source-event membership; any discrimination differences arise from field retention.
- **No head-to-head LogApprox/CPR performance comparison.** The forensic-validity literature evaluates overlapping but distinct purposes; comparisons are conceptual unless separately implemented.

## Execution

From repository root (both OTRF ZIP files already available and checked by D03/D07):

```bash
python scripts/run_d08_claim_discrimination.py
PYTHONPATH=src:. python -m pytest -q
```

The command prints a summary and writes `outputs/d08_claim_discrimination/d08_case_results.csv`, `d08_summary.json`, and `d08_manifest.json`. Check `agreement`, `false_supported`, `false_excluded`, both abstention counts, and the three-by-three status matrix. If `predeclared_criteria_met` is false, preserve the discrepancy and revisit the inference, not the frozen cases.

## Interpretation and decision gate

A positive contract test is **not** a claim of independently measured detection accuracy or sufficient publication novelty. The cases were selected and expected states were explicitly stipulated from the same two credential-access source archives used during framework development. The missing-field outcomes are consequences of declared encodings and logical rules. A two-valued comparator necessarily collapses indeterminate into not-supported by its definition. These are transparent design checks, not a representative statistical sample of SOC activity.

If all outcomes align, D08 supports a narrow assertion: an explicit three-outcome audit preserves the distinction between decidable unit-local absence and representation-induced undecidability in these controlled cases. It does not support a broad empirical advantage over published forensic-validity or logging-sufficiency approaches. If the JISA contribution requires that stronger claim, the current experimental programme has not established it; a change of manuscript positioning or venue may be warranted.
