# D06.1 — Pre-registered aggregation-representation design

Status: design only. No D06 experiment has been run and no user repository files have been modified.

Repository baseline: `dtrap-reproducibility-revision` at `2c9e3f6` (as verified by user); D03, D04, D05 retained unchanged.

## Research question

What is the relationship between aggregation payload reduction and recovery of declared, structured security-evidence claims when all policies receive the same fixed source stream? Separate evidence preservation from measured analyst utility or calibrated host-compromise inference.

## Fixed reference and boundaries

* Read the original Mordor NDJSON ZIP, enumerate lines, and verify each raw line's normalized SHA-256 and line-based ID against the D03 fixed inventory. Verify D03 manifest and inventory/evidence SHA-256 before running. The inventory is an evaluation oracle, never a feature source for the encoders.
* Keep the fixed D03 evidence reference of 6,026 records, four structured LSASS-access records, one documented-agent match; do not recompute that reference after aggregation.
* Source EventID 10 has 272 records in the raw trace; this is a descriptive count, not a new D06 result.
* Distinguish true Sysmon UtcTime (679 records overall; all four evidence events) from the 5,347 indexed-time fallbacks. Use the existing D03 timestamp for initial host/absolute-UTC grouping; report timestamp-basis composition and run a timestamp-basis sensitivity analysis. Never represent the fallback as verified source-time telemetry.
* All methods use one grouping partition: normalized host plus floor(event_seconds / window_seconds), with 5, 10, and 30 s UTC-aligned windows. Encoders cannot use D03 annotation flags, the documented agent PID, LSASS names, or a D03 source ID list to select or filter events.

## Representations

P0 (raw reference): Original event fields; preserve the source record identity and its original event time. No aggregation. Count its serialized payload and maintain it as the reconstruction reference.

P1 (count-only): A group contains `(host, bucket_start_utc, bucket_end_utc, record_count)`. It exposes no event IDs or structured fields.

P2 (structured process-access): Each group contains the P1 header, an event-type histogram for all records, and a list of distinct **joint** tuples `(EventID, normalized SourceImage, normalized TargetImage, multiplicity)` for Sysmon EventID 10. These tuples preserve source–target association, avoiding fabricated cross-products from independent lists. No process ID or source event ID. For non-EventID 10 types, only the event-type histogram is retained. No scenario-specific selectors.

P3 (structured provenance-aware): Same headers and event-type histogram as P2, with process-access tuples `(EventID, normalized SourceImage, normalized TargetImage, SourceProcessId, multiplicity)` and source timestamp range. Include an optional source-event-ID witness list per tuple, measured as separate `P3-with-witnesses` variant if implemented, **not** silently free provenance. All process-access types are processed uniformly, without LSASS-specific selection. C may be reconstructed only by joining the source PID and host to *external scenario documentation* in the evaluator, not inside the encoder. Distinguish a witnessed event identity from a mere claim signature.

Use canonical, deterministic UTF-8 JSONL serialization with sorted keys, stable tuple ordering and documented string normalization (case-insensitive Windows path basenames) to calculate bytes. Also report gzip bytes, since JSON structural repetition can distort uncompressed comparisons. State that serialized size is a proxy, not measured storage/compute/network cost.

## Recovery contract

For each policy, reconstruct only from its serialized output, in a separate decoder that cannot access the original record, D03 labels, or internal source grouping. Evaluate recovery against the fixed D03 oracle using comparable observable claims:

* A: `EventID==10` and `basename(TargetImage)==lsass.exe`.
* B: A and `basename(SourceImage)==powershell.exe`.
* C: B, normalized host WORKSTATION5, and `SourceProcessId==1648`, where the host/PID association is declared *only* in the evaluation configuration and sourced to original scenario documentation.

Return one of `{supported, unsupported, indeterminate}` for each group/claim. `unsupported` is valid only when the retained representation is complete enough to exclude the claim. Missing fields yield `indeterminate`, not a negative claim. For group-level checks, use the fixed source membership only in the evaluator to determine whether a group truly contains an A/B/C witness. For policy P3 with aggregate tuples but without source IDs, distinguish support for a claim from recovery of the exact D03 source-event identity. Do not label an aggregate claim as event-level recovery unless its witness source-event ID is exposed.

For ledger replay: process emitted aggregates by arrival time, not original event time, preserving group and tuple multiplicity only where exposed. Maintain `K` as the union of supported A/B/C claims. An indeterminate claim does not enter `K`. Never use precomputed D03 indicator columns as ledger input. Reporting `K` does not imply security-state correctness or SOC usefulness.

## Timing assumptions

Treat raw records as an *idealized* zero-additional-delay comparison, not operational ingestion measurements. For aggregation, assume a non-streaming tumbling window is emitted at `bucket_end + 0 s` and explicitly report `(emission_time - evidence_event_time)` as synthetic buffering latency. Keep 180 s per-event deadline for D04/D05 comparability, but also report shorter 5, 10, and 30 s deadlines because <=30 s windows cannot ordinarily reveal a 180 s timing penalty. Do not infer real transportation latency. The 5/10/30 s short deadline test is a design sensitivity, not incident-response validation.

## Measurements

1. Source records (fixed at 6,026) and number of aggregate units by policy and window; preserve `source_count / aggregate_unit_count` as a count ratio only.
2. Canonical serialized bytes and gzip bytes for P0–P3, plus any witness-ID overhead variant. Never equate unit-count reduction to storage/computation savings.
3. Claims A/B/C recovered (`supported`), indeterminate or unsupported; false supported claims and false exclusions against the fixed D03 oracle; separately report group-level and event-ID-level recoverability.
4. Maintained ledger final claim coverage and first available time by claim, for each reconstruction policy.
5. Deadline-qualified claim coverage with explicit synthetic window-emission delays and timestamp-basis stratification.
6. Ambiguity or overclaim rate: any decoder claim not justified by a retained **joint** field tuple; detect false cross-field joins with adversarial synthetic fixtures.

## Acceptance tests (must precede claims)

* Reference integrity: corrupt raw source line or D03 manifest yields error; original row identity unambiguous; stable output across repeat runs.
* Encoder blindness: adding/removing D03 evidence flags from input cannot change serialized policy outputs; no evidence flag or documented PID hard-coded in encoder.
* No label leakage: decoder receives serialized aggregate only and scenario-documentation C mapping; evaluator alone receives D03 oracle.
* Joint tuple safety: synthetic group `{powershell -> benign.exe, svchost -> lsass.exe}` must NOT yield B or C; independent column-set cross-product is unacceptable.
* Nested claim constraints: C implies B implies A; C without observable PID is indeterminate, not supported.
* Mixed groups and duplicates: one relevant record among many unrelated events, multiple repeated tuples, case/path normalization, and malformed/missing fields.
* Evidence-vs-identity: P3 may support claim C even without source IDs; exact source-event recovery requires optional witness IDs.
* Timing: event close to window boundary versus early in window, aggregation emission order, shorter deadlines; fallback timestamp record identifiable as fallback.
* Reconciliation: raw P0 reproduces D03 A=4 event witnesses, B=1, C=1; aggregation controls compared against D04 only where definitions match; no insistence that all D04 outputs should match new policy semantics.
* Determinism: exact output SHA-256 stable across two runs, full existing test suite passes; no mutation of D03–D05 outputs.

## Study limitations and decision gate

This is a single attack scenario, not SOC operational validation. P2/P3 are declared handcrafted encodings, not typical commercial aggregation implementations. Successful A/B/C recovery under P3 may follow from preserving their defining fields; the informative comparison is payload/ambiguity/timing/provenance trade-off and robustness across cases, not 'P3 detects attacks'. A second independent scenario or task should be considered before making broad JISA novelty claims. If P3 retaining generic process access attributes costs nearly as much as raw data or if alternative encodings perform equivalently, report that as a boundary rather than suppressing it.

## Planned implementation (D06.2, only after design is frozen)

Proposed new files: `scripts/run_d06_aggregation_representation.py`, `tests/test_d06_aggregation_representation.py`, `docs/results/d06_aggregation_representation_comparison.md`, and `outputs/d06_aggregation_representation/{policy_outputs.jsonl,summary.csv,claim_reconstruction.csv,manifest.json}` (exact naming can be refined before implementation). Keep D03–D05 unchanged. Run tests then commit implementation and generated outputs separately on `dtrap-reproducibility-revision`.
