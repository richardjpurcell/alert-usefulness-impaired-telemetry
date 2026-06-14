# First Synthetic Result: Delivery and Usefulness Separate Under Telemetry Impairment

## Purpose

This note records the first complete synthetic ASTRA result.

The purpose of this experiment is not to model a real SOC environment in detail. The purpose is to verify that the ASTRA pipeline can express and measure the central research claim:

> Security telemetry that arrives is not always useful.

The first synthetic sweep shows that delivery rate, alert volume, and usefulness fraction can separate under controlled telemetry impairments.

## Pipeline

The experiment uses the current ASTRA synthetic pipeline:

```text
latent incident state
    → generated telemetry
    → impaired telemetry
    → defender belief
    → usefulness diagnostics
    → figures and summaries
```

The implemented surfaces are:

```text
src/astra/incident_state.py   # latent host compromise state
src/astra/telemetry.py        # generated telemetry events
src/astra/impairments.py      # delay, loss, noise, suppression, flood
src/astra/belief.py           # defender belief update surface
src/astra/metrics.py          # usefulness diagnostics
src/astra/visualization.py    # first-pass figures
src/astra/experiments.py      # orchestration
```

## Experiment design

The impairment sweep compares six conditions:

| Experiment                      | Impairment interpretation                                  |
| ------------------------------- | ---------------------------------------------------------- |
| `exp01_synthetic_baseline`      | healthy telemetry                                          |
| `exp02_delay_impairment`        | telemetry arrives late                                     |
| `exp03_loss_impairment`         | telemetry is dropped                                       |
| `exp04_noise_impairment`        | false positives and false negatives are introduced         |
| `exp05_adversarial_suppression` | telemetry from compromised hosts is selectively suppressed |
| `exp06_alert_flood`             | large numbers of low-value synthetic alerts are added      |

Each condition uses the same synthetic incident-state and telemetry-generation framework, then applies a different impairment regime before updating defender belief and computing usefulness diagnostics.

## Key output

A recent run produced the following summary:

| Experiment                      | Delivery rate | Useful-event fraction | Stale-event fraction |
| ------------------------------- | ------------: | --------------------: | -------------------: |
| `exp01_synthetic_baseline`      |         1.000 |                 0.967 |                0.000 |
| `exp02_delay_impairment`        |         1.000 |                 0.548 |                0.281 |
| `exp03_loss_impairment`         |         0.697 |                 0.962 |                0.000 |
| `exp04_noise_impairment`        |         0.995 |                 0.843 |                0.000 |
| `exp05_adversarial_suppression` |         0.500 |                 0.935 |                0.000 |
| `exp06_alert_flood`             |         6.000 |                 0.161 |                0.000 |

The most important result is not which condition is “best.” The important result is that the metrics separate.

## Main interpretation

### 1. Delay preserves delivery but reduces usefulness

The delay condition has a delivery rate of `1.000`, the same as the healthy baseline, but its useful-event fraction drops from `0.967` to `0.548`.

This is the cleanest first demonstration of the ASTRA claim. Telemetry arrives, but part of it arrives too late to remain useful for belief maintenance. Delivery alone therefore overstates the health of the monitoring pipeline.

### 2. Loss reduces delivery but not necessarily usefulness fraction

The loss condition has a delivery rate of `0.697`, but the useful-event fraction remains high at `0.962`.

This does not mean loss is harmless. It means the conditional usefulness of delivered events can remain high even when many generated events fail to arrive. A delivery metric and a usefulness metric answer different questions:

* delivery rate asks how much telemetry arrived;
* useful-event fraction asks how much of the arrived telemetry helped.

Both are needed.

### 3. Noise keeps delivery high while lowering usefulness

The noise condition has a delivery rate of `0.995`, close to the baseline, but usefulness drops to `0.843`.

This shows another form of separation. The telemetry stream remains mostly present, but its evidential quality is degraded by false positives and false negatives.

### 4. Adversarial suppression can make delivered telemetry look useful

The adversarial suppression condition has a delivery rate of `0.500`, but a useful-event fraction of `0.935`.

This is a useful caution. Delivered telemetry may appear useful conditional on arrival, while the missing telemetry is precisely what matters. This condition suggests that ASTRA should report both conditional usefulness and missingness/suppression diagnostics.

### 5. Alert flood increases delivery volume while collapsing usefulness

The alert-flood condition has a delivery rate of `6.000` because the system receives many more events than were originally generated. However, the useful-event fraction drops to `0.161`.

This is the strongest alert-volume result. More alerts do not imply better defender knowledge. In this condition, telemetry volume increases while usefulness collapses.

## Figure outputs

The current run produces the following first-pass figures:

```text
outputs/figures/delivery_vs_usefulness.png
outputs/figures/belief_quality.png
outputs/figures/exp06_alert_flood_usefulness_label_counts.png
```

These figures support three visual claims:

1. delivery rate and useful-event fraction separate;
2. belief quality degrades under some impairments;
3. alert flood is dominated by low-usefulness flood events.

## Scientific claim supported by this result

This first synthetic result supports the following bounded claim:

> In a controlled synthetic security-telemetry setting, delivery rate and alert volume do not reliably indicate whether delivered telemetry improves defender belief. Delay, noise, adversarial suppression, and alert flood create distinct separations between telemetry arrival and telemetry usefulness.

This is not yet a claim about real SOC data. It is a proof-of-concept result showing that the ASTRA artifact can represent and measure the separation that the paper is about.

## Why this matters for the paper

This result gives the paper its first empirical spine.

A conventional telemetry-health framing might emphasize event delivery, drop rate, or alert volume. ASTRA instead asks whether telemetry helps maintain a useful defender belief state. The first sweep shows why that distinction matters:

```text
high delivery does not guarantee usefulness
low delivery does not fully describe usefulness
high alert volume can actively obscure usefulness
```

The result also motivates dataset-backed follow-up experiments. The next stage should test whether similar separations can be observed in adversary-emulation traces such as Mordor / OTRF-style datasets.

## Current limitations

This result is intentionally preliminary.

Known limitations:

* the incident-state model is synthetic;
* the telemetry-generation model is heuristic;
* the belief update model is simple and not calibrated to analyst behavior;
* usefulness labels are operational proxies;
* alert-flood and noise models are stylized;
* no real SOC/SIEM dataset has been used yet.

These limitations should be described openly. The value of the result is that the pipeline is now complete and produces the intended separation under controlled conditions.

## Immediate next steps

Recommended next steps:

1. Add a short table-export helper for paper-facing summary tables.
2. Improve figure labels so experiment names are shorter and more readable.
3. Add a dataset-adapter design note for Mordor / OTRF traces.
4. Add a second synthetic scenario where adversarial suppression lowers both delivery and belief quality.
5. Begin drafting the paper’s first experiment section from this note.

## Reproduction commands

From the project root:

```bash
conda activate astra
pytest
python experiments/exp01_synthetic_separation.py
python experiments/exp02_impairment_sweep.py
```

To regenerate figures:

```bash
python - <<'PY'
from astra.visualization import make_sweep_figures, make_label_count_figure

outputs = make_sweep_figures()
for name, path in outputs.items():
    print(name, path)

path = make_label_count_figure(
    "outputs/tables/exp06_alert_flood_usefulness_label_counts.csv",
    "outputs/figures/exp06_alert_flood_usefulness_label_counts.png",
    title="Usefulness-state composition: alert flood",
)
print("alert_flood_labels", path)
PY
```

Expected test status at this checkpoint:

```text
42 passed
```
