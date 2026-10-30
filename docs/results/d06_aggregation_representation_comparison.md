# D06.2 — Aggregation-representation comparison

Status: controlled, deterministic experiment; **not** operational SOC validation. D06.1 design was frozen in `docs/design/d06_aggregation_representation_design.md` before implementation. D03–D05 source and outputs remain unchanged.

## Research question and reference

Compare how much payload each declared representation retains, and whether a decoder using **only serialized output** can reconstruct three fixed evidence claims. All policies receive the same original 6,026-event OTRF Mordor Empire Mimikatz trace. D03 fixes four structured LSASS process-access records (claim A), one PowerShell-to-LSASS record (B), and one association with the scenario-documented host/PID (C). None is a validated host-compromise label.

The script verifies SHA-256 for the raw archive, its NDJSON member, D03 inventory and evidence files, and each raw line's immutable source-record ID and SHA-256. It rejects modified inputs. D03 flags enter **only the evaluator**, never the policy encoder or decoder.

## Policies and interpretation

- **P0 raw:** complete records, event IDs and time metadata; idealized zero additional buffering. Byte counts include JSON record bodies, source IDs and the experiment's time metadata, so this is not an optimized transport comparison.
- **P1 count:** host, UTC-aligned tumbling window and event count only. Claims are *indeterminate*, not absent.
- **P2 joint:** P1 plus an EventID histogram and `(EventID, SourceImage basename, TargetImage basename, multiplicity)` joint tuples for **all** Sysmon EventID 10 records. It preserves paired image attributes and A/B, not source PID or event identity. In a group where B is supported, C is *indeterminate*.
- **P3 PID:** P2 plus source-process PID in the same joint tuple and the source-UTC timestamp range (where available). The declared scenario host/PID join is performed only by the decoder. P3 can support C, but without source-event IDs cannot recover a particular original record's identity.

All policies use the same host and absolute UTC 5/10/30 s windows. Non-streaming aggregates are emitted at window end without additional transport latency. Sizes are deterministic canonical UTF-8 JSONL and gzip byte counts; they **do not measure** processing cost or actual SIEM storage/network cost.

## Results

| Policy | Window | Units | JSONL bytes | gzip bytes | A-supported groups | B-supported groups | C-supported groups |
|---|---:|---:|---:|---:|---:|---:|---:|
| P0 raw | — | 6,026 | 44,381,901 | 744,090 | 4 records | 1 record | 1 record |
| P1 count | 5 s | 90 | 10,936 | 762 | 0 | 0 | 0 |
| P2 joint | 5 s | 90 | 20,862 | 1,983 | 3 | 1 | 0 |
| P3 PID | 5 s | 90 | 27,013 | 2,848 | 3 | 1 | 1 |
| P1 count | 10 s | 53 | 6,444 | 511 | 0 | 0 | 0 |
| P2 joint | 10 s | 53 | 13,788 | 1,596 | 3 | 1 | 0 |
| P3 PID | 10 s | 53 | 17,632 | 2,180 | 3 | 1 | 1 |
| P1 count | 30 s | 21 | 2,561 | 285 | 0 | 0 | 0 |
| P2 joint | 30 s | 21 | 7,510 | 1,232 | 2 | 1 | 0 |
| P3 PID | 30 s | 21 | 9,463 | 1,551 | 2 | 1 | 1 |

The count of A-supporting **groups** falls as multiple original A records occupy the same window; this must not be interpreted as disappearance of evidence. P1 counts yield indeterminate claims. P2 preserves the structured association for A/B but lacks the PID needed for C, so C is indeterminate for the relevant group rather than unsupported. P3 recovers all three declared claim types. Across the aggregate comparison, no false supported claims or false exclusions were found under the constructed D03 oracle. P1/P2/P3 expose **zero original source IDs**, so none receives event-identity recovery credit.

At 5 s, including PID plus source timestamp range costs **865 additional gzip bytes** compared with P2 (2,848 vs 1,983). The actual effect of adding the fields is policy-dependent and cannot establish an operational cost saving. All aggregated policies yield the same number of audit units within a window because the grouping keys are fixed.

## Synthetic timeliness

The P3 policy's four A-witnesses meeting synthetic buffering deadlines are:

| Window | Within 5 s | Within 10 s | Within 30 s |
|---|---:|---:|---:|
| 5 s | 4 / 4 | 4 / 4 | 4 / 4 |
| 10 s | 3 / 4 | 4 / 4 | 4 / 4 |
| 30 s | 1 / 4 | 1 / 4 | 4 / 4 |

For C, the documented-agent record satisfies even the five-second synthetic deadline in each grouping. All four A-witnesses satisfy the 180-second deadline. These are *window-end buffering* measurements, not network latency or SOC response times.

## Timestamp-basis sensitivity

Of 6,026 source records, only 679 have a source-side `UtcTime`; 5,347 use an explicitly marked index-time fallback. All four declared evidence witnesses have source `UtcTime`. As a diagnostic (not a replacement main experiment), a separate table repeats the representation comparison using only 679 source-time records. A/B/C supported-group outcomes are identical for all windows and policies; aggregate-unit counts change (e.g., 90 to 74 at 5 s). This does not validate the true event times for fallback records, but reduces concern about timestamp mixing for these **particular** claim witnesses.

## Interpretation and scientific boundary

P3's ability to reconstruct C is a consequence of retaining the defining PID field. D06 is not an attack-detection benchmark, cannot estimate useful-alert prevalence or belief accuracy, and supplies no operational SOC utility evidence. The measurable result is a controlled information representation trade-off: **count-only aggregation loses queryability; joint attributes preserve more semantic evidence; PID adds scenario-specific linkage at an explicit serialized byte cost**. The original claim that event delivery and usefulness diverge is not independently validated by D06.

This is one trace and three nested claims. P2/P3 are experimental representations, not commercial SOC aggregators. To support a stronger JISA contribution, compare against alternative tasks/scenarios or a defended realistic aggregation baseline, preferably with out-of-sample predeclared security questions. Keep this result as a bounded methodological demonstration unless such evidence is added.

## Reproduce

From repository root:

```bash
python scripts/run_d06_aggregation_representation.py
PYTHONPATH=src:. python -m pytest -q
```

Produces `outputs/d06_aggregation_representation/` with `policy_outputs/*.jsonl`, `d06_policy_summary.csv`, `d06_claim_reconstruction.csv`, `d06_source_time_sensitivity.csv`, and `d06_experiment_manifest.json`. Each serialized output is deterministic; checksum manifests and tests verify reproducibility. Raw archive `data/raw/mordor/empire_mimikatz_logonpasswords.zip` and D03 outputs are required.
