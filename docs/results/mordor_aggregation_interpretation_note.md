# Mordor aggregation interpretation note

This note summarizes what the Mordor real-data bridge now demonstrates after
the belief/usefulness, saturation, weight-sensitivity, aggregation, and
state-mapping checks.

## Context

ASTRA now includes a small real-data bridge from a Mordor-derived security
telemetry scenario into the same belief/usefulness diagnostic structure used by
the synthetic experiments.

The current Mordor scenario is:

```text
Empire Mimikatz LogonPasswords
```

The processed telemetry is mapped into an ASTRA generated-telemetry frame,
passed through impairment models, used to update defender belief, and evaluated
with usefulness diagnostics.

The bridge is intentionally experimental. It does not claim SOC-grade ground
truth. It tests whether ASTRA's central distinction can be exercised on
realistic security telemetry:

```text
Security telemetry that arrives is not always useful.
```

## What the bridge demonstrates

The Mordor bridge demonstrates that ASTRA's information-delivery versus
information-usefulness distinction can be applied beyond synthetic telemetry.

The pipeline now supports:

```text
processed Mordor events
    -> generated-like ASTRA telemetry
    -> impairment
    -> belief update
    -> usefulness diagnostics
    -> summary tables
```

This is important because the thesis/paper claim is not only that artificial
examples can separate delivery from usefulness. The claim is that this
separation is relevant to real telemetry-like data as well.

## Delivery-side separation

The impairment runs show familiar delivery-side separations:

| Mode | Delivery-side interpretation |
|---|---|
| healthy | all generated events are delivered |
| delay | events are delivered, but some arrive late |
| loss | events are missing |
| noise | delivered volume can increase while represented original evidence falls |
| duplication | delivered volume inflates without adding original evidence |
| alert flood | delivered volume doubles, but much of the added traffic is flood |
| adversarial suppression | selected events are removed |

This supports a basic ASTRA point:

```text
Counting delivered events is not enough.
```

The same or larger delivered volume can mean very different things depending on
whether the telemetry is timely, duplicated, noisy, flooded, or selectively
suppressed.

## Belief/usefulness-side separation

The first belief/usefulness run showed that most healthy Mordor-derived events
were labelled redundant under the scalar host-compromise belief abstraction.

That initially looked surprising, but the interpretation checks explained why:

```text
Repeated evidence quickly saturated the scalar belief near its upper bound.
```

Once the belief was saturated, additional similar events could still be
delivered, but they no longer changed the belief state. In ASTRA terms, they
were delivered but not belief-improving.

This is a useful result because it shows that redundancy is not only an
impairment artifact. Redundancy can arise from repeated real telemetry even in a
healthy channel.

## Weight sensitivity

The weight-sensitivity check showed that reducing belief update weights delays
saturation somewhat, but does not eliminate the dominant pattern.

The main interpretation is:

```text
Saturation is partly weight-sensitive, but repeated-event structure is the
larger driver.
```

This matters because it prevents overinterpreting the first result as merely a
bad choice of belief weights. Lower weights change the degree of saturation, but
the repeated nature of the Mordor event stream remains central.

## Aggregation result

The event-aggregation sensitivity check collapsed repeated raw events into
host/window/event/state evidence units.

The main result was:

| Mode | Generated/evidence units | Source events represented | Redundant | Misleading | Saturated fraction |
|---|---:|---:|---:|---:|---:|
| raw | 6,026 | 6,026 | 5,986 | 33 | 0.993 |
| aggregated | 44 | 6,026 | 18 | 26 | 0.409 |

The aggregation result is important because it separates two issues that were
mixed together in the raw event stream:

1. repeated telemetry caused belief saturation;
2. state abstraction affects how usefulness labels should be interpreted.

Aggregation sharply reduced saturated redundant updates. However, it also made
the remaining state-abstraction issue more visible.

## State-mapping result

The state-mapping helper branch made the Mordor state abstraction explicit:

```text
normalize_mordor_observed_state(...)
mordor_state_is_true_signal(...)
```

The impact check confirmed that making the mapping explicit did not disrupt the
existing results. This is a maintainability and interpretability improvement,
not a scientific-model change.

The current mapping should be understood as an ASTRA evaluation abstraction:

```text
Mordor-derived state labels are not SOC-grade ground truth.
```

This boundary is important. It prevents the analysis from overstating what the
Mordor bridge proves.

## What this does not demonstrate

The current Mordor bridge does not demonstrate that ASTRA can assign
operationally correct usefulness labels to arbitrary SOC telemetry.

It also does not demonstrate:

- validated incident ground truth;
- analyst-grade alert triage;
- complete ATT&CK-stage modelling;
- causal attribution of compromise;
- production SOC readiness;
- a universal cybersecurity belief model.

The current bridge is narrower. It demonstrates that the ASTRA diagnostic
structure can be connected to a real telemetry trace and that the delivery versus
usefulness separation remains visible.

## Paper-facing interpretation

A careful paper-facing interpretation would be:

```text
In a Mordor-derived Empire Mimikatz LogonPasswords trace, ASTRA's diagnostic
pipeline exposes separations between delivered telemetry volume, represented
original evidence, belief updates, redundancy, staleness, flood effects, and
state-abstraction limits. The result is not an operational SOC classifier, but a
real-data bridge showing that arrival-side telemetry measures and
belief-side usefulness diagnostics can diverge in realistic security telemetry.
```

A shorter version:

```text
The Mordor bridge shows that the delivery/usefulness distinction survives
contact with realistic security telemetry, while also exposing the modelling
care required when defining the state against which usefulness is judged.
```

## Recommended wording for limitations

Use language like:

```text
The Mordor experiment is a bridge experiment rather than an operational
validation. Its purpose is to test whether ASTRA's diagnostic concepts can be
exercised on realistic security telemetry, not to claim analyst-grade ground
truth or production alert triage.
```

Avoid wording like:

```text
ASTRA correctly identifies useful and misleading Mordor alerts.
```

A better version is:

```text
ASTRA labels updates as useful, redundant, stale, misleading, or flood-relative
to the explicit belief and state abstraction used in the experiment.
```

## Main contribution of the Mordor bridge

The Mordor sequence now supports this claim:

```text
Realistic telemetry can be abundant, deliverable, and still diagnostically
uneven: repeated events can saturate belief, impairments can alter represented
evidence, floods can inflate volume, and usefulness labels depend on the state
abstraction being maintained.
```

That is closely aligned with the project thesis:

```text
Security telemetry that arrives is not always useful.
```

## Recommended next step

The next research step should not be to make the model more complex
immediately. A better next step is to decide which of two directions matters
most:

1. a paper-facing synthesis of the existing Mordor bridge; or
2. a new design branch for richer event-stage or scenario-phase abstractions.

If the goal is a concise paper result, stop here and write the bridge as a
bounded real-data demonstration.

If the goal is stronger cybersecurity modelling, the next design target should
be event-stage abstraction, not more weight tuning.
