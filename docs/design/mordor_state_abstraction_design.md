# Mordor state abstraction design

This design note records the next modelling issue exposed by the Mordor
belief/usefulness bridge: the current state abstraction is too crude for judging
belief usefulness in aggregated real security telemetry.

## Context

ASTRA has now carried Mordor-derived telemetry through several real-data
bridges:

```text
normalized Mordor telemetry
    -> generated-like ASTRA telemetry frame
    -> impairment
    -> defender belief update
    -> usefulness diagnostics
    -> reporting
```

The raw event-level bridge showed that repeated Mordor records quickly saturate
the scalar host-compromise belief. A weight-sensitivity check showed that lower
belief weights delay saturation only slightly. An event-aggregation sensitivity
check reduced 6,026 raw records to 44 evidence units and lowered the saturated
update fraction from 0.993 to 0.409.

However, aggregation exposed another issue: many aggregated evidence units were
labelled misleading under the current state abstraction.

## Current abstraction

The current Mordor bridge maps the processed Mordor field:

```text
observed_state -> source_state
```

and then uses:

```text
observed_state != benign -> is_true_signal
```

The belief/usefulness layer evaluates updates against a host-by-time state table
built from these `source_state` values.

This is intentionally simple and was appropriate for the first bridge. It lets
the ASTRA pipeline run end-to-end on real telemetry without claiming operational
ground truth.

## Problem

The current `observed_state` / `source_state` abstraction is doing too many jobs.

It is being used as:

1. the event's source-side state label;
2. the generated telemetry's `source_state`;
3. the latent host state used to judge belief error;
4. a proxy for whether an event is a true signal;
5. the reference against which usefulness labels are assigned.

Those roles are related, but they are not identical.

For example, an event can be meaningful evidence of credential access or
attacker activity even if the delivery-time host state abstraction is not
`compromised`. Under the current diagnostic, an event that increases compromise
belief when the delivery-time state is not compromised can be labelled
misleading. This may be internally consistent for the current abstraction, but
it is not necessarily a SOC-grade interpretation.

## Why this matters

ASTRA's core claim is:

```text
Security telemetry that arrives is not always useful.
```

To support that claim with real telemetry, ASTRA needs a defensible state
abstraction. The state abstraction does not need to be operational ground truth,
but it must be clear about what question it supports.

The current abstraction answers a narrow question:

```text
Did this event move scalar host-compromise belief in the direction implied by
the current simplified host state label?
```

That is useful as a first diagnostic, but it may be too narrow for Mordor-style
attack traces, where security value may depend on stage, persistence, repeated
evidence, or activity type rather than only host compromise at a time step.

## Design principle

Do not claim more truth than the dataset and mapping provide.

The next abstraction should remain explicitly experimental:

```text
Mordor-derived state labels are ASTRA evaluation abstractions, not SOC-grade
incident truth.
```

The goal is to improve interpretability, not to pretend that ASTRA has solved
alert ground-truth labelling.

## Option 1: Keep host compromise as the only belief target

Retain the current scalar belief:

```text
P(host is compromised)
```

but document that Mordor usefulness labels are only about movement of that
scalar belief.

### Advantages

- Minimal change.
- Preserves comparability with prior synthetic experiments.
- Easy to explain.

### Disadvantages

- Many meaningful security events may appear misleading or redundant.
- Does not distinguish credential access, suspicious activity, compromise, and
  persistence.
- Keeps too much pressure on one scalar state.

### Best use

Keep as the baseline and reference model.

## Option 2: Normalize states into a simple ordered host-stage abstraction

Map Mordor-derived states into a small ordered set:

```text
benign
suspicious
compromised
```

This is close to the current abstraction but should be made explicit and
validated in one place.

Possible rule:

```text
benign       -> benign
suspicious   -> suspicious
compromised  -> compromised
other/unknown -> suspicious
```

The belief target could remain binary:

```text
compromised vs not compromised
```

but the state table would be cleaner and less ad hoc.

### Advantages

- Small implementation change.
- Makes the current mapping explicit and testable.
- Helps avoid hidden state-label drift.

### Disadvantages

- Still collapses attack-stage information.
- Still judges all usefulness against compromise belief.

### Best use

Good immediate cleanup if code currently spreads state assumptions across
multiple places.

## Option 3: Track multiple belief targets

Instead of one scalar host-compromise belief, track several belief surfaces:

```text
P(host has suspicious activity)
P(host has credential-access evidence)
P(host is compromised)
```

For this Mordor scenario, credential-access evidence is especially relevant
because the selected scenario is Empire Mimikatz LogonPasswords.

### Advantages

- Better aligned with the scenario.
- Reduces the burden on `compromised` as the only useful target.
- Allows an event to be useful for credential-access belief even if it is not
  useful for compromise belief.

### Disadvantages

- Larger model change.
- Requires new belief update logic and diagnostics.
- May be too much for the next small branch.

### Best use

Promising longer-term direction.

## Option 4: Add an event-stage label separate from host state

Keep the host-state table simple, but add a separate event-stage abstraction.

Example event stages:

```text
benign_activity
suspicious_activity
credential_access_evidence
compromise_support
synthetic_flood
```

Then usefulness diagnostics can distinguish:

```text
event evidence stage
host state at generated time
host state at delivery time
belief movement
```

### Advantages

- Separates event meaning from host state.
- Fits security telemetry better.
- Avoids forcing all event usefulness into host-compromise truth.

### Disadvantages

- Requires a small taxonomy.
- Needs careful wording to avoid overclaiming.
- Diagnostics become more complex.

### Best use

Good candidate for the next design-to-code step.

## Option 5: Evaluate usefulness against scenario phase

For Mordor scenarios, create a scenario-phase timeline and evaluate whether
events support the current phase.

Example phases:

```text
pre-activity
initial access / suspicious activity
credential access
post-credential-access activity
```

For Empire Mimikatz LogonPasswords, a credential-access phase could be used as
the main evidence target.

### Advantages

- Better aligned with attack narratives.
- Useful for paper framing.
- Makes real-data interpretation more meaningful.

### Disadvantages

- Scenario-specific.
- Less general than host-state diagnostics.
- Requires manual or semi-manual phase mapping.

### Best use

Useful for a later paper-facing analysis, not the smallest next code branch.

## Recommended immediate approach

Do not replace the belief model yet.

The next small implementation branch should add an explicit Mordor state mapping
helper and a documentation/test surface around it.

Suggested branch:

```bash
git checkout -b exp36-mordor-state-mapping-helper
```

Suggested goal:

```text
Add a small, tested Mordor state-normalization helper that makes the current
state abstraction explicit, centralized, and documented.
```

This should not change the scientific results much. Its value is that it makes
the current abstraction visible and testable before more ambitious modelling
changes.

## Suggested helper behaviour

A first helper could expose:

```python
normalize_mordor_observed_state(value: str) -> str
mordor_state_is_true_signal(value: str) -> bool
```

Initial mapping:

| Raw observed state | Normalized state | True signal |
|---|---|---:|
| `benign` | `benign` | false |
| `suspicious` | `suspicious` | true |
| `compromised` | `compromised` | true |
| missing/unknown/other | `suspicious` | true |

The `unknown -> suspicious` rule should be treated as conservative and
experimental, not operational truth.

## Tests

Add small tests that verify:

1. known states normalize as expected;
2. capitalization and whitespace are handled;
3. unknown states follow the documented fallback;
4. true-signal mapping is consistent with normalized state;
5. the Mordor generated-telemetry bridge uses the helper.

## Interpretation boundary

This branch should not claim to solve Mordor ground truth. It should only make
ASTRA's current real-data state abstraction explicit.

The main scientific claim remains:

```text
Security telemetry that arrives is not always useful.
```

The state-abstraction work clarifies the reference against which usefulness is
judged.
