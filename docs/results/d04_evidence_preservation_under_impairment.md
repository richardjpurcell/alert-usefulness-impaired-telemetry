# D04 — Evidence preservation under controlled telemetry impairment

**Status:** Reproduced from the fixed D03 evidence inventory; **not** an operational SOC or host-compromise validation study.

## Research question

When a fixed adversary-emulation trace is subjected to controlled telemetry loss, delay, or aggregation, how much of a separately declared source-evidence subset remains (i) physically represented, (ii) identifiable to an audit consumer, and (iii) identifiable by a declared deadline?

This experiment deliberately does **not** use the manuscript's scalar host-compromise update model, severity scores, or heuristic `compromised` labels.

## Fixed reference and definitions

The D03 reference contains 6,026 original records, four structured `EventID=10`, `TargetImage=lsass.exe` records, and one documented-host/PowerShell/PID match (`WORKSTATION5`, PowerShell process 1648). These event selections describe *available telemetry evidence*, not verified compromise outcomes. D04 enforces the D03 inventory and evidence-table SHA-256 hashes at runtime and never reconstructs the source reference from the impaired stream.

- **Physically represented:** the source record survives loss or remains a constituent of an aggregate, according to the experiment's internal provenance mapping.
- **Identifiably available:** its source ID and declared evidence classification remain accessible to a downstream audit consumer.
- **Timely identifiable:** identifiable with a synthetic delivery shift of at most **180 seconds** from the D03 event timestamp. The baseline synthetic delay is zero; this is **not** a measurement of original SOC transport latency.
- **Evidence subset:** four LSASS process-access events, including one documented-agent-associated PowerShell event. Outcomes are reported per *fixed reference event*, including dropped events; denominators do not shrink when evidence is lost.

## Conditions

- **Healthy:** all 6,026 source records retained, with zero added delay.
- **Loss:** independent Bernoulli removal at rates 0.10, 0.30 and 0.50, over seeds 1–10. Each run draws in D03 source-inventory order.
- **Delay:** each event independently receives a synthetic shift of 60, 240, or 600 seconds with probability 0.30, seeds 1–10. No events are dropped. Delays over 180 seconds miss the declared deadline.
- **Aggregation:** absolute UTC time buckets of 5, 10, and 30 seconds, grouping by `host` only. Two deliberately contrasting **projection policies** use exactly the same group membership: `count_only` retains host/window/count but hides source IDs and evidence fields; `provenance_preserving` retains those details. The produced `d04_aggregation_projections.csv` materializes the actual projected group records. This is **not** the original manuscript's grouping rule, and group counts must not be directly compared with its aggregation results.

The two aggregation policies are constructed controls. The observation that count-only groups cannot reveal individual evidence is true **by design**, not an empirical discovery about deployed aggregators. The purpose is to establish an inspectable contract for a later, genuine field-retention comparison.

## Results

### Fixed evidence survival under random loss

| Loss rate | Mean represented source fraction, 10 seeds | LSASS records retained across 10 runs (out of 40) | Documented-agent record retained (out of 10 runs) |
|---|---:|---:|---:|
| 10% | 0.9002 | 38 | 8 |
| 30% | 0.7008 | 32 | 7 |
| 50% | 0.4982 | 28 | 6 |

These small evidence counts are **realized outcomes of the declared random draws**, not reliable estimates of detection probability. In particular, survival of a single reference event has high sampling variability.

### Synthetic delivery delay

| Added delay, applied to 30% of records | Physically represented LSASS events (out of 40 across 10 runs) | Identifiable by 180-second deadline | Documented-agent event identifiable by deadline (out of 10) |
|---|---:|---:|---:|
| 60 s | 40 | 40 | 10 |
| 240 s | 40 | 32 | 7 |
| 600 s | 40 | 32 | 7 |

The two above-deadline delay conditions have identical *deadline outcomes* under the same seeds because they delay the same selected records. This does not mean their latencies are equivalent.

### Constructed aggregation-projection contrast

| Bucket | Aggregated groups | Source records physically represented | LSASS identifiable in count-only | LSASS identifiable with retained provenance |
|---|---:|---:|---:|---:|
| 5 s | 90 | 6,026 | 0/4 | 4/4 |
| 10 s | 53 | 6,026 | 0/4 | 4/4 |
| 30 s | 21 | 6,026 | 0/4 | 4/4 |

The difference between projections is **guaranteed by the explicitly chosen serialization rules**. It shows why retained *volume* and recoverable *evidence identity* must be measured separately, but does not independently validate an alert-aggregation method.

## Timing and validity limitations

D03 records report 679 source `UtcTime` values and 5,347 explicit `@timestamp` fallbacks. The four selected structured LSASS events use Sysmon UTC event time. D04 treats the chosen D03 timestamp as the baseline for a *synthetic shift* and does **not** infer network transit delay or rely on cross-source clock alignment.

The source-event identity and indicator columns come from D03, which describes structured evidence but does not independently establish host-compromise truth. The documented-agent indicator uses a declared association to the emulation transcript, not a validated SOC detection label. The fixed indicator subset is tiny, and ten seeds cannot support population-level SOC claims. Aggregation policies are declared behavior controls, and identifiable recovery depends on those declarations.

**Interpretation:** D04 operationalizes a reproducible *evidence availability* audit independent of the current belief model. Its constructed controls are useful for testing the audit pipeline, but they do not yet establish the usefulness or correctness of maintained security beliefs. A subsequent model must use independently justified state targets and explicitly distinguish changes to evidence from changes to its interpretation.

## Reproduction

From the repository root, after D03 outputs are generated and verified:

```bash
python scripts/run_d04_evidence_preservation.py
PYTHONPATH=src:. python -m pytest -q
```

Output files:

- `outputs/d04_evidence_preservation/d04_condition_summary.csv` — 67 conditions (healthy, 30 loss, 30 delay, 6 aggregation projections).
- `outputs/d04_evidence_preservation/d04_fixed_evidence_outcomes.csv` — 268 individual evidence-record outcomes (4 fixed records × 67 conditions).
- `outputs/d04_evidence_preservation/d04_aggregation_projections.csv` — 328 explicit grouped projections under the two serialization policies.
- `outputs/d04_evidence_preservation/d04_experiment_manifest.json` — fixed input fingerprints, parameter values, definitions, caveats and output checksums.

No original manuscript experiment, source dataset, or D03 output is altered.
