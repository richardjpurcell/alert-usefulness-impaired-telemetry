# D05 — Maintained evidence-state ledger (unaggregated replay)

**Status:** D05 prototype with fixed D03 reference and D04-compatible healthy/loss/delay controls. This is **not** a maintained probability of compromise or a validation of SOC decision usefulness.

## Purpose and evaluation boundary

**Question:** When source events arrive, which *declared evidence claims* become newly represented, which are repeated, and which are unavailable by a declared per-event deadline?

D03 identifies a fixed subset of four structured LSASS process-access records in a 6,026-event Mordor trace; one of the four is associated with the scenario-documented PowerShell agent. D04 establishes fixed-reference physical representation and timeliness under controlled impairments. D05 moves from these availability measurements to a **maintained, explicitly nonprobabilistic claim set**, without using a constructed host-compromise target.

The claims are nested and not mutually exclusive:

- **A — LSASS access:** Sysmon `EventID=10` with `TargetImage=lsass.exe`.
- **B — PowerShell-to-LSASS:** A plus `SourceImage=powershell.exe`.
- **C — Documented-agent signature:** B on the documented host (`WORKSTATION5`) with PowerShell source process ID 1648. This is **scenario-documentation-assisted**, not a claim that a deployed detector independently recognized the agent.

No event changes a compromise label. D05 treats the D03 indicator columns as a declared source-side *annotation oracle* for a controlled ledger experiment. These indicators are not general security truths. The experiment does **not** assume that other events can independently establish absence of evidence or non-compromise.

## Update model

Let `K` be the set of acquired claims `{A,B,C}` and `K_180` a second set containing claims available within the **synthetic per-event** latency limit of 180 seconds. Both begin empty.

For each delivered event `e` in **arrival order**, let `c(e)` be the claims supplied by its D03 annotations. Define:

- `new(e) = c(e) \ K` immediately before the update;
- `repeat(e) = c(e) ∩ K`;
- `K <- K ∪ c(e)`;
- `K_180 <- K_180 ∪ c(e)` **only when** the synthetic delivery shift is at most 180 seconds.

An event is `new_claim` if `new(e)` is nonempty, `repeat_claim` if it supports claims but supplies none that are new, or `no_claim` if no claim is supported. The outcome is a property of this declared ledger, **not** an intrinsic useful/redundant/misleading alert label. A late event can update `K` after the deadline and leave `K_180` unchanged.

A record dropped by a loss condition is absent from the delivered-event updates; its identity remains in the **fixed D03 evidence population** in the evaluation trace and is marked `dropped`. This preserves fixed denominators.

## Experiments and controlled comparison

The healthy replay is deterministic. Loss conditions independently drop events at 10%, 30%, and 50% over seeds 1–10. Delay conditions independently delay 30% of records by 60, 240, or 600 seconds over the same ten seeds. D05 uses the exact D04 random-draw order (D03 inventory order), but processes surviving events in **delivery timestamp order**, with source-event ID as a deterministic tie-breaker.

D05 deliberately excludes D04's **aggregation** conditions. Its existing count-only representation does not expose individual structured claims; its provenance-preserving representation passes precomputed D03 evidence annotations, which would make successful recovery of the claims guaranteed by serialization. A proper aggregation-aware evidence ledger must first specify which raw, independently inspectable fields survive grouping. That is a separate design task.

## Results from the fixed D03 source

Healthy: 6,026 delivered events; **two events add at least one previously absent claim**, two events repeat existing claims, and 6,022 support none of these narrowly declared claims. All three claims A, B, C become represented, through two evidence-bearing updates. This is **not** a claim that 6,022 events are useless in security operations.

| Condition | Runs | Runs with A in complete ledger | Runs with B/C in complete ledger | Runs with B/C by synthetic 180-s deadline |
|---|---:|---:|---:|---:|
| Healthy | 1 | 1 | 1 | 1 |
| 10% loss | 10 | 10 | 8 | 8 |
| 30% loss | 10 | 10 | 7 | 7 |
| 50% loss | 10 | 10 | 6 | 6 |
| 60-s delay | 10 | 10 | 10 | 10 |
| 240-s delay | 10 | 10 | 10 | 7 |
| 600-s delay | 10 | 10 | 10 | 7 |

**Interpretation:** With this *explicitly chosen evidence definition*, receipt of 6,026 events does not by itself show which claims were acquired. A synthetic long-delay condition can produce an identical complete ledger but a different by-deadline ledger. The exact outcomes for A/B/C largely follow from D03 labels and D04 impairment draws: this is a **controlled accounting demonstration**, not a validated improvement in alert prioritization, incident knowledge, or security response.

A/B/C are nested, and the current trace has one B/C record. Thus the B/C survival results merely restate the survival of that source record under the configured impairment and should not be presented as independent corroborating evidence or a novel statistical association.

## Checks and caveats

- D03 manifest and source/evidence CSV SHA-256 fingerprints are verified before replay.
- D05 delivered-event counts and documented-agent survival/timeliness agree with D04 for all 61 unaggregated conditions.
- Arrival order is explicit; late evidence can enter the complete ledger but not the deadline-qualified ledger.
- Source-event IDs and D03 evidence identities are immutable. No reference target is rebuilt from impaired observations.
- The observation time basis is mixed: 679 `source_UtcTime` records and 5,347 labelled index-time fallbacks. The four evidence records use `source_UtcTime`. Synthetic delay is relative to D03 time and is **not** a measurement of actual transport latency.
- Claim sets are monotonic and cannot represent contradictory evidence, decay, revoked evidence, provenance uncertainty, or independence of corroborating sources.
- The experiment cannot establish a correctly calibrated security-state probability or operational SOC utility.

**Scientific gate before claiming novelty:** A publishable methodological result must show that the ledger supports an informative query, robust inference, or decision-relevant comparison not already provided by fixed-source evidence counts. D05 alone does **not** pass that bar. We should next test a realistic field-retaining aggregation (or a richer, independently justified state/decision task), not simply add more synthetic conditions.

## Reproduction

From repository root (with D03 outputs present):

```bash
python scripts/run_d05_evidence_ledger.py
PYTHONPATH=src:. python -m pytest -q
```

Outputs:

- `outputs/d05_evidence_ledger/d05_ledger_summary.csv` (61 condition rows).
- `outputs/d05_evidence_ledger/d05_evidence_update_trace.csv` (4 fixed evidence records × 61 conditions = 244 rows).
- `outputs/d05_evidence_ledger/d05_ledger_manifest.json` (definitions, checksums, configuration, caveats).

No existing D03/D04 outputs, original Mordor experiments, or manuscript files are modified.
