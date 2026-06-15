# Mordor impairment summary

This note records ASTRA's first impairment summary over extracted Mordor / OTRF telemetry.

## Scenario

Scenario:

```text
Empire Mimikatz LogonPasswords
```

ASTRA scenario slug:

```text
empire_mimikatz_logonpasswords
```

Input event stream:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

The processed CSV is generated locally and ignored by git.

## Script

The impairment summary was produced with:

```text
scripts/run_mordor_impairment_experiment.py
```

The script performs the following bridge:

```text
normalized Mordor telemetry
    → ASTRA generated-telemetry-like frame
    → apply_impairment
    → summarize_impairment
    → impairment summary table
```

This step intentionally stops at impairment summaries. It does not yet run defender belief updates or usefulness diagnostics.

## Local result

Output table:

```text
outputs/tables/mordor_impairment_summary.csv
```

Summary:

```text
scenario,impairment_mode,generated_events,delivered_events,synthetic_flood_events,duplicate_events,delayed_events,missing_generated_events,delivery_rate,represented_delivery_rate
empire_mimikatz_logonpasswords,healthy,6026,6026,0,0,0,0,1.0,1.0
empire_mimikatz_logonpasswords,delay,6026,6026,0,0,1862,0,1.0,1.0
empire_mimikatz_logonpasswords,loss,6026,4164,0,0,0,1862,0.6910056422170594,0.6910056422170594
empire_mimikatz_logonpasswords,noise,6026,6052,0,0,0,1179,1.0043146365748423,0.8043478260869565
empire_mimikatz_logonpasswords,duplication,6026,7888,0,1862,0,0,1.3089943577829406,1.0
empire_mimikatz_logonpasswords,alert_flood,6026,12052,6026,0,0,0,2.0,1.0
empire_mimikatz_logonpasswords,adversarial_suppression,6026,5904,0,0,0,122,0.9797543976103551,0.9797543976103551
```

## Interpretation

This is the first real-data result showing that ASTRA's impairment machinery can be applied to an extracted security telemetry stream.

The result is already useful because the impairment modes behave differently:

```text
healthy
    All generated events are delivered.

delay
    All generated events remain represented, but 1,862 events are delayed.

loss
    1,862 generated events are missing, reducing both delivery rate and represented delivery rate.

noise
    Delivered-event volume slightly exceeds the generated-event count, but represented delivery falls to about 0.804.

duplication
    Delivered-event volume increases to about 1.309 times the generated-event count, while represented delivery remains 1.0.

alert_flood
    Delivered-event volume doubles because 6,026 synthetic flood events are added, while represented delivery remains 1.0.

adversarial_suppression
    122 generated events are missing, producing a smaller but targeted delivery degradation.
```

The central ASTRA point appears in the Mordor-derived setting:

```text
More delivered telemetry does not necessarily mean more represented original evidence.
Less delivered telemetry does not describe which evidence was lost.
Delay preserves delivery counts while changing timeliness.
Flood and duplication inflate delivery counts without increasing represented original evidence.
```

## What this does and does not show

This result shows that a real extracted Mordor / OTRF telemetry stream can pass through ASTRA's impairment layer.

It does not yet show whether the delivered events improved defender belief. That requires the next layer:

```text
impaired Mordor telemetry
    → defender belief update
    → usefulness diagnostics
```

## Limitations

The Mordor extraction and mapping rules remain first-pass and scenario-specific.

The bridge from Mordor telemetry into ASTRA's generated-telemetry-like schema uses experimental mappings:

```text
event_time      → time step
severity        → event_score
observed_state  → source_state
observed_state != benign → is_true_signal
```

These mappings support an experiment about telemetry delivery and impairment. They are not SOC-grade labels, universal ground truth, or a complete security-event ontology.

## Next step

The next step should connect the Mordor impairment output to ASTRA's belief and usefulness diagnostics.

A narrow next branch should answer:

```text
Given the same extracted Mordor stream, which impairment modes preserve delivery but degrade belief usefulness?
```

That would move the Mordor result from delivery-side impairment into ASTRA's core question:

```text
Security telemetry that arrives is not always useful.
```
