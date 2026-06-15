# Mordor belief saturation options

This design note records modelling options after the first Mordor
belief/usefulness runs.

## Context

The first Mordor belief/usefulness bridge successfully carried real
Mordor-derived telemetry through:

```text
normalized Mordor telemetry
    -> generated-like ASTRA telemetry frame
    -> impairment
    -> defender belief update
    -> usefulness diagnostics
    -> summary table
```

The healthy Mordor run produced:

- useful events: 7
- redundant events: 5,986
- misleading events: 33

The interpretation check showed that most events were labelled redundant
because scalar host compromise belief quickly saturated at the configured
maximum probability of 0.999. Once saturated, later events could not materially
change belief or entropy.

## Current behaviour

The current ASTRA belief model is intentionally simple:

- each host has one scalar belief: `P(host is compromised)`;
- each delivered event applies an event-type and score-based update;
- beliefs are clipped between configured minimum and maximum probabilities;
- synthetic flood events are penalized;
- missing events do not directly update belief.

This is useful as a first diagnostic surface, but repeated real telemetry can
drive the scalar belief to saturation quickly.

## Why this matters

The saturation behaviour is not necessarily a bug. It is a modelling choice
with consequences.

It makes the current model easy to explain:

```text
early evidence changes belief;
later repeated evidence becomes redundant once belief saturates.
```

But it may under-represent useful repeated evidence in real security telemetry,
where repeated events can matter because they indicate persistence, escalation,
lateral movement, or confidence reinforcement.

## Option 1: Keep saturation as the baseline

Retain the current scalar belief model as ASTRA's simplest baseline.

### Advantages

- Transparent and easy to explain.
- Good first bridge from synthetic telemetry to real telemetry.
- Redundancy has a clear meaning: no additional belief movement.
- Avoids overfitting the first Mordor scenario.

### Disadvantages

- Repeated real alerts quickly become redundant.
- Useful persistence signals may be flattened.
- The useful-event count may look artificially low.

### Best use

Use this as the reference model for all future alternatives.

## Option 2: Lower Mordor-derived event weights

Introduce a Mordor-specific or real-data-specific belief configuration with
smaller event update weights.

### Advantages

- Simple to implement.
- Reduces immediate saturation.
- Preserves the existing belief-update structure.

### Disadvantages

- Requires choosing new weights.
- Could look arbitrary without calibration.
- Does not address repeated evidence structurally.

### Best use

Useful as a sensitivity experiment, not as the final model.

## Option 3: Add diminishing returns for repeated events

Reduce the update magnitude for repeated event types on the same host within a
local time window.

Example:

```text
first endpoint alert on host h: full weight
second similar alert soon after: reduced weight
later repeated alerts: further reduced weight
```

### Advantages

- Matches the intuition that repeated identical alerts add less new evidence.
- Reduces saturation without ignoring repeated telemetry.
- Keeps event-level diagnostics.

### Disadvantages

- Requires defining similarity and time windows.
- Adds statefulness to the belief updater.
- Could complicate interpretation.

### Best use

Good candidate for a future small modelling branch.

## Option 4: Aggregate events before belief update

Aggregate Mordor events into host/time windows before applying belief updates.

Example aggregation keys:

```text
host_id
time window
event_type family
maximum severity
count of events
```

### Advantages

- Better suited to high-volume real telemetry.
- Reduces repeated-event flooding.
- Produces more interpretable update units.

### Disadvantages

- Moves away from event-level telemetry diagnostics.
- Aggregation choices affect results.
- May hide important event ordering.

### Best use

Good candidate if ASTRA moves toward episode-level or analyst-facing summaries.

## Option 5: Track confidence separately from compromise belief

Separate the belief that a host is compromised from confidence in that belief.

Example:

```text
belief_compromised: probability host is compromised
belief_confidence: strength or support behind that probability
```

Repeated events might increase confidence even when compromise probability is
already high.

### Advantages

- Captures reinforcement without forcing probability past saturation.
- Better reflects repeated evidence.
- Distinguishes "high belief with weak support" from "high belief with strong support."

### Disadvantages

- Larger model change.
- Requires new metrics and tests.
- More difficult to explain in the first ASTRA paper.

### Best use

Promising longer-term direction, but probably too large for the next immediate
implementation branch.

## Option 6: Add evidence ageing or confidence decay

Allow belief or confidence to relax over time unless refreshed by new telemetry.

### Advantages

- Makes repeated observations useful when they maintain belief.
- Aligns with the idea that stale security telemetry loses value.
- Connects naturally to delay and timeliness impairments.

### Disadvantages

- Requires careful time-scale choices.
- May interact with existing `decay_to_prior`.
- Needs more interpretive testing.

### Best use

Good future direction after the baseline and saturation behaviour are documented.

## Option 7: Evaluate usefulness at episode level

Shift some usefulness diagnostics from individual events to episode-level
security stages.

Example stages:

```text
initial suspicious activity
credential access indication
host compromise support
persistence or repeated evidence
suppression/flood/noise effect
```

### Advantages

- Better aligned with security-analysis workflows.
- Avoids over-interpreting thousands of repeated events.
- Gives a more paper-friendly bridge from telemetry to usefulness.

### Disadvantages

- Requires scenario-specific abstraction.
- Less generic than the current event-level model.
- Needs careful wording to avoid claiming SOC-grade truth.

### Best use

Useful for a later ASTRA paper framing, not the immediate next code change.

## Recommended next step

Do not replace the current model yet.

The next implementation branch should run one small sensitivity experiment:
lower the belief-update weights for Mordor-derived telemetry and compare the
healthy-mode label distribution against the current baseline.

Suggested branch:

```bash
git checkout -b exp32-mordor-belief-weight-sensitivity
```

Suggested goal:

```text
Add a Mordor belief sensitivity script that compares default belief weights
against one or two lower-weight configurations.
```

This keeps the current model intact while showing whether the observed
redundancy is primarily a weight/saturation effect.
