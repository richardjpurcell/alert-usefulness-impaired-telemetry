# ASTRA: Alert Usefulness Under Impaired Security Telemetry

ASTRA is a small research artifact for studying the difference between **security telemetry that arrives** and **security telemetry that is useful** for maintaining a defender’s belief about compromise.

The core idea is simple:

> Security telemetry that arrives is not always useful.

Modern security operations environments can be alert-rich while still leaving defenders uncertain, misled, overloaded, or poorly coupled to the underlying incident state. ASTRA provides a controlled experimental pipeline for testing this separation under delay, loss, noise, adversarial suppression, and alert flood conditions.

## Research purpose

ASTRA is not an intrusion detection system, SIEM replacement, or operational SOC tool. It is a bounded research instrument for asking:

* How does telemetry impairment affect defender belief?
* When does delivery rate fail to reflect usefulness?
* Which impairments preserve event arrival while degrading belief quality?
* When do alerts become stale, redundant, misleading, or uninformative?
* How can alert usefulness be audited separately from alert volume?

The artifact supports a paper direction tentatively framed as:

**Alert Usefulness Under Impaired Security Telemetry**

## Pipeline

ASTRA currently implements a first-pass synthetic experiment pipeline:

```text
latent incident state
    → generated telemetry
    → impaired telemetry
    → defender belief
    → usefulness diagnostics
    → figures and summaries
```

Each surface is implemented as a separate module:

```text
src/astra/incident_state.py   # latent host compromise state
src/astra/telemetry.py        # generated security telemetry
src/astra/impairments.py      # delay, loss, noise, flood, suppression
src/astra/belief.py           # defender belief update surface
src/astra/metrics.py          # usefulness diagnostics
src/astra/visualization.py    # first-pass paper-facing figures
src/astra/experiments.py      # experiment orchestration
```

## Current impairment modes

ASTRA currently supports:

| Mode                      | Interpretation                                           |
| ------------------------- | -------------------------------------------------------- |
| `healthy`                 | telemetry arrives without impairment                     |
| `delay`                   | events arrive late                                       |
| `loss`                    | events are dropped                                       |
| `noise`                   | false positives and false negatives are introduced       |
| `adversarial_suppression` | events from compromised hosts are selectively suppressed |
| `alert_flood`             | large numbers of low-value synthetic alerts are added    |
| `duplication`             | generated events are duplicated                          |

## Usefulness labels

Delivered events are classified into first-pass diagnostic labels:

| Label           | Meaning                                                   |
| --------------- | --------------------------------------------------------- |
| `useful`        | event improves belief error or reduces entropy            |
| `stale`         | event arrives after a configured staleness threshold      |
| `redundant`     | event produces negligible belief and entropy change       |
| `misleading`    | event worsens belief error                                |
| `uninformative` | event arrives but does not help enough to count as useful |
| `flood`         | synthetic flood/background event                          |

These labels are intentionally operational and auditable. They are not presented as universal definitions of analyst usefulness.

## Installation

Create and activate a conda environment:

```bash
conda create -n astra python=3.11
conda activate astra
```

Install the project in editable mode:

```bash
pip install -e .
```

Run the test suite:

```bash
pytest
```

Current expected result:

```text
42 passed
```

## Running experiments

Run the baseline synthetic experiment:

```bash
python experiments/exp01_synthetic_separation.py
```

Run the impairment sweep:

```bash
python experiments/exp02_impairment_sweep.py
```

The sweep writes outputs under:

```text
outputs/tables/
outputs/manifests/
outputs/figures/
outputs/logs/
```

Generated outputs are ignored by git by default.

## Example first-pass result

A recent synthetic sweep produced the following pattern:

| Experiment              | Delivery rate | Useful-event fraction | Interpretation                                                      |
| ----------------------- | ------------: | --------------------: | ------------------------------------------------------------------- |
| baseline                |         1.000 |                 0.967 | high delivery, high usefulness                                      |
| delay                   |         1.000 |                 0.548 | delivery preserved, usefulness degraded by staleness                |
| loss                    |         0.697 |                 0.962 | fewer events arrive, but those arriving are often useful            |
| noise                   |         0.995 |                 0.843 | delivery remains high, usefulness drops                             |
| adversarial suppression |         0.500 |                 0.935 | many events are missing, but delivered events may still look useful |
| alert flood             |         6.000 |                 0.161 | alert volume explodes while usefulness collapses                    |

This is the central separation ASTRA is designed to expose:

> Delivery rate alone does not certify useful security telemetry.

## Creating figures

After running the sweep, create the standard figures:

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

Current first-pass figures include:

```text
outputs/figures/delivery_vs_usefulness.png
outputs/figures/belief_quality.png
outputs/figures/exp06_alert_flood_usefulness_label_counts.png
```

## Configuration files

Experiments are configured with YAML files in:

```text
configs/
```

Current configs include:

```text
configs/synthetic_baseline.yaml
configs/impairment_delay.yaml
configs/impairment_loss.yaml
configs/impairment_noise.yaml
configs/impairment_adversarial_suppression.yaml
configs/impairment_alert_flood.yaml
```

Each config specifies an experiment slug, network size, telemetry generation parameters, impairment settings, belief settings, and usefulness-diagnostic thresholds.

## Development workflow

The project has been developed surface-by-surface:

```text
incident state
telemetry generation
telemetry impairment
defender belief
usefulness diagnostics
experiment runner
visualization
```

The current branch history follows small, test-backed milestones. Before committing new changes, run:

```bash
pytest
git status
```

## Repository status

At the current artifact checkpoint, ASTRA includes:

* synthetic latent incident-state generation;
* generated security telemetry;
* multiple telemetry impairment operators;
* a defender belief update surface;
* event-level usefulness diagnostics;
* experiment orchestration;
* first-pass figures;
* a passing test suite.

## Current limitations

ASTRA is currently a synthetic proof-of-concept. Important limitations include:

* the incident-state model is deliberately simple;
* the belief update model is heuristic rather than a calibrated Bayesian SOC model;
* usefulness labels are operational proxies;
* dataset-backed experiments are not yet implemented;
* figures are first-pass and intended for inspection, not final publication.

These limitations are intentional at this stage. The purpose is to establish the research pipeline and show that telemetry delivery and telemetry usefulness can be separated under controlled conditions.

## Next steps

Near-term development targets:

1. Improve the synthetic experiment note and document the first result.
2. Add dataset adapters, starting with Mordor / OTRF-style adversary-emulation traces.
3. Expand usefulness diagnostics for redundancy, misleadingness, and alert fatigue.
4. Add more paper-facing plots and tables.
5. Create a reproducibility bundle for the first ASTRA result.

## License

License to be determined.
