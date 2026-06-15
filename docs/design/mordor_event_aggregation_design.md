# Mordor event aggregation design

This design note proposes a small event-aggregation step for Mordor-derived
telemetry in ASTRA.

## Context

The first Mordor belief/usefulness bridge showed that real telemetry can be
carried through ASTRA's pipeline:

```text
normalized Mordor telemetry
    -> generated-like ASTRA telemetry frame
    -> impairment
    -> defender belief update
    -> usefulness diagnostics
    -> summary table
```

Follow-up interpretation and sensitivity checks showed that most healthy
Mordor events are labelled redundant because the current scalar host-belief
model quickly saturates. Lowering belief weights delays saturation slightly,
but does not remove the repeated-event pattern.

This suggests that repeated-event structure, not only update weight, should be
handled explicitly.

## Problem

Mordor-derived telemetry contains many repeated event records. In the current
event-level bridge, each record becomes a separate belief-update opportunity.

That is useful for testing delivery impairments, but it can overstate the
number of belief-update opportunities. Once host belief saturates, thousands of
later records become redundant under the current diagnostic.

This does not mean the events are operationally useless. It means that the
current event-level abstraction is too literal for high-volume repeated
security telemetry.

## Proposed minimal aggregation

Add an optional preprocessing step that aggregates Mordor-derived generated
telemetry before impairment and belief update.

The aggregation unit should be:

```text
host_id
time_window
event_family
source_state
```

For the first implementation, use a fixed integer time window over ASTRA time
steps.

Example:

```text
aggregation_window_steps = 5
```

Events with times 0--4 are assigned to window 0, times 5--9 to window 5, and
so on.

## Event family

For the first version, keep event family simple.

Use the existing `event_type` value as the event family:

```text
event_family = event_type
```

Do not yet create a SOC-specific taxonomy.

This keeps aggregation transparent and avoids claiming more semantic knowledge
than the current Mordor bridge supports.

## Aggregated output schema

The aggregated dataframe should preserve ASTRA's generated telemetry schema:

```text
event_id
time
host_id
event_type
event_score
source_state
is_true_signal
```

It should add optional aggregation metadata:

```text
source_event_count
max_event_score
mean_event_score
aggregation_window_start
aggregation_window_end
```

The core ASTRA impairment layer should still be able to consume the dataframe
using the existing generated-telemetry columns.

## Aggregation rules

For each group:

```text
host_id
window_start
event_type
source_state
```

construct one aggregated event.

Recommended field rules:

| Field | Rule |
|---|---|
| `event_id` | deterministic aggregation id |
| `time` | window start |
| `host_id` | group host |
| `event_type` | group event type |
| `event_score` | maximum event score in group |
| `source_state` | group source state |
| `is_true_signal` | any source event is true signal |
| `source_event_count` | number of source records in group |
| `max_event_score` | maximum source event score |
| `mean_event_score` | mean source event score |
| `aggregation_window_start` | window start |
| `aggregation_window_end` | window start + window size - 1 |

Use maximum score rather than mean score as the core `event_score` because the
aggregated event should preserve the strongest evidence in that local window.

## Why aggregate before impairment?

Aggregation should happen before impairment in this first design:

```text
normalized Mordor telemetry
    -> generated-like ASTRA telemetry
    -> aggregation
    -> impairment
    -> belief update
    -> usefulness diagnostics
```

This allows impairments to operate on analyst-facing telemetry units rather
than raw repeated records.

For example:

- loss means an aggregated alert unit is lost;
- delay means an aggregated alert unit is delayed;
- duplication means an aggregated alert unit is duplicated;
- flood still adds synthetic non-evidence events.

This is simpler than impairing raw records first and aggregating later.

## Expected effect

Aggregation should reduce the number of repeated belief-update opportunities.

Expected directional effects:

| Metric | Expected change |
|---|---|
| generated events | decrease |
| delivered events | decrease under healthy mode |
| redundant events | decrease |
| saturated update fraction | decrease |
| useful event fraction | may increase |
| mean belief delta | may increase or remain similar |
| represented delivery rate | should remain interpretable |

The main research question is not whether aggregation makes the numbers look
better. It is whether aggregation creates a more appropriate unit of evidence
for repeated security telemetry.

## First experiment

The first implementation should compare:

```text
raw Mordor generated telemetry
aggregated Mordor telemetry, window = 5
aggregated Mordor telemetry, window = 10
aggregated Mordor telemetry, window = 30
```

Use healthy mode only at first.

Suggested output:

```text
outputs/tables/mordor_event_aggregation_sensitivity.csv
```

Suggested columns:

```text
scenario
aggregation_mode
aggregation_window_steps
generated_events
delivered_events
source_event_count
useful_events
redundant_events
misleading_events
uninformative_events
flood_events
useful_event_fraction
redundant_event_fraction
mean_belief_delta
mean_entropy_delta
mean_belief_error_delta
belief_mean_belief_entropy
belief_mean_belief_error
saturated_updates
saturated_update_fraction
```

## Tests

Add focused unit tests for the aggregation helper:

1. Aggregation preserves required generated-telemetry columns.
2. Aggregation reduces repeated records in a small sample.
3. Aggregation uses maximum event score.
4. Aggregation records `source_event_count`.
5. Aggregation is deterministic.

Do not test the full Mordor dataset in detail. Keep tests small and synthetic.

## Interpretation boundary

Aggregation is not a claim that raw Mordor records are duplicates or useless.
It is a modelling choice about the unit of evidence passed into ASTRA's belief
surface.

The current raw-event bridge should remain available as the baseline.

## Recommended next branch

Suggested implementation branch:

```bash
git checkout -b exp34-mordor-event-aggregation-sensitivity
```

Goal:

```text
Add an optional Mordor generated-telemetry aggregation helper and compare raw
versus aggregated healthy-mode belief/usefulness diagnostics.
```
