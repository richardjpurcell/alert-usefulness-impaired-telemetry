# Mordor belief/usefulness summary

This note records the first ASTRA run that carries Mordor-derived telemetry
through impairment, defender belief updating, and usefulness diagnostics.

## Scenario

- Dataset family: Mordor / OTRF Security Datasets
- Scenario: Empire Mimikatz LogonPasswords
- Scenario slug: `empire_mimikatz_logonpasswords`
- Processed input: `data/processed/empire_mimikatz_logonpasswords_events.csv`
- Generated events: 6,026

## Pipeline

```text
normalized Mordor telemetry
    -> generated-like ASTRA telemetry frame
    -> impairment
    -> defender belief update
    -> usefulness diagnostics
    -> summary table
```

## Outputs

- `outputs/tables/mordor_belief_usefulness_summary.csv`
- `outputs/tables/mordor_belief_usefulness_label_counts.csv`

## Summary

| Impairment mode | Delivery rate | Represented delivery rate | Main usefulness-side effect |
|---|---:|---:|---|
| healthy | 1.000 | 1.000 | 6,026 events delivered; mostly redundant updates |
| delay | 1.000 | 1.000 | 1,798 stale events despite complete delivery |
| loss | 0.702 | 0.702 | 1,798 generated events missing |
| noise | 1.011 | 0.811 | delivered volume increases while represented delivery falls |
| duplication | 1.298 | 1.000 | duplicate volume inflates delivery without adding represented evidence |
| alert_flood | 2.000 | 1.000 | 6,026 flood events added |
| adversarial_suppression | 0.981 | 0.981 | 112 generated events missing |

## Interpretation

The first Mordor-based belief/usefulness run preserves the project’s central
separation between telemetry arrival and telemetry usefulness.

Delay preserves both delivery rate and represented delivery rate, but creates
1,798 stale updates. Loss reduces both delivery and represented delivery.
Noise slightly increases delivered volume while reducing represented delivery
to about 0.811. Duplication and alert flooding inflate delivered volume without
increasing represented original evidence. Alert flooding doubles delivered
volume and produces 6,026 flood-labelled updates.

The healthy run produces 7 useful updates, 5,986 redundant updates, and 33
misleading updates. This should not yet be interpreted as a SOC-grade
measurement of alert usefulness. It reflects the current ASTRA belief/update
abstraction applied to Mordor-derived telemetry.

## Interpretation boundary

The Mordor-to-ASTRA mapping is an experimental abstraction. In particular,
`observed_state` is used as the state abstraction, severity is mapped to an
event score, and non-benign observations are treated as true-signal events.
This is sufficient for an ASTRA proof-of-concept bridge, but it is not
SOC-grade alert truth.

## Main point

The first real-data bridge now connects delivered telemetry volume to
belief/usefulness diagnostics. This allows ASTRA to compare arrival-side
metrics, such as delivery rate and represented delivery rate, with downstream
diagnostics such as useful, stale, misleading, redundant, uninformative, and
flood-labelled updates.

The result supports the project claim:

```text
Security telemetry that arrives is not always useful.
```
