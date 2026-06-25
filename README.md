# Alert Usefulness Under Impaired Security Telemetry

This repository contains the experiment code, configurations, processed inputs, derived outputs, figures, and notes for the paper:

**Alert Usefulness Under Impaired Security Telemetry**

The core idea is simple:

> Security telemetry that arrives is not always useful.

The project studies how security telemetry can be delivered, counted, aggregated, or impaired while still failing to improve a maintained defender-role estimate of the security state. It is intended as a research artifact for alert-usefulness auditing, not as an intrusion detector, SIEM replacement, SOC product, or analyst-performance study.

## Research purpose

The repository supports an alert-usefulness audit framework for distinguishing:

* telemetry delivery;
* represented delivery;
* alert/event volume;
* aggregation;
* impairment effects; and
* belief-side usefulness.

Usefulness is interpreted in a narrow audit-relative sense: contribution to a specified belief-maintenance process under an explicit belief model, state abstraction, aggregation rule, and impairment model.

The audit labels delivered events or evidence units using diagnostic states such as useful, redundant, stale, misleading, and flood-relative. These labels are not universal operational SOC labels. They describe how evidence behaves under the declared audit design.

## Paper framing

The associated paper asks whether delivered security telemetry improves a maintained defender-role estimate of host compromise, attack progression, or response priority under controlled impairment.

The paper’s real-data bridge uses the Mordor / OTRF Security Datasets, specifically the *Empire Mimikatz LogonPasswords* adversary-emulation scenario. In the paper, “bridge” means a controlled mapping from processed security events into the evidence units, belief updates, impairments, aggregation settings, and diagnostic labels required by the audit model.

The Mordor bridge is not operational SOC validation. It is a bounded experiment showing that the delivery/usefulness distinction can be exercised on realistic adversary-emulation telemetry.

## Repository structure

```text
configs/       Experiment configuration files
data/          Processed inputs and raw-data notes
docs/          Design notes, dataset notes, and result interpretation notes
experiments/   Experiment entry points
outputs/       Derived figures, manifests, and tables
scripts/       Mordor extraction, validation, experiment, and figure scripts
src/astra/     Core audit implementation
tests/         Unit and integration tests
```

## Pipeline

The audit pipeline maps security telemetry into a belief-maintenance and diagnostic workflow:

```text
source security events
    → audit telemetry stream
    → impairment and aggregation
    → belief update for the defender role
    → usefulness diagnostics
    → tables and figures
```

The main implementation modules are:

```text
src/astra/incident_state.py   # incident-state abstractions
src/astra/telemetry.py        # telemetry records and generated telemetry
src/astra/impairments.py      # delay, loss, noise, flood, duplication, suppression
src/astra/belief.py           # defender-role belief update surface
src/astra/metrics.py          # usefulness diagnostics
src/astra/reporting.py        # summary tables and reporting helpers
src/astra/visualization.py    # figure generation
src/astra/datasets.py         # dataset-related helpers
src/astra/experiments.py      # experiment orchestration
```

## Impairment and aggregation modes

The experiments include controlled conditions such as:

| Mode                      | Interpretation                                                        |
| ------------------------- | --------------------------------------------------------------------- |
| `healthy`                 | telemetry is replayed without impairment                              |
| `delay`                   | events arrive late relative to the audit window                       |
| `loss`                    | source events are removed before delivery                             |
| `noise`                   | event attributes or mappings are corrupted                            |
| `duplication`             | delivered event volume increases through repeated events              |
| `alert_flood`             | additional flood events increase volume without proportional evidence |
| `adversarial_suppression` | selected relevant events are removed                                  |
| `aggregation`             | raw events are grouped into evidence units before belief update       |

Aggregation changes the audit object. A raw replay asks how each event affects the maintained estimate, while an aggregated replay asks how grouped evidence units affect that estimate.

## Usefulness labels

Delivered events or evidence units are classified into audit-relative diagnostic labels:

| Label                      | Meaning                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------- |
| `useful`                   | reduces uncertainty or moves the maintained estimate toward the audited scenario state                    |
| `redundant`                | repeats evidence already reflected in the current belief state                                            |
| `stale`                    | arrives too late for the relevant audit window                                                            |
| `misleading`               | moves the maintained estimate away from the audited scenario state or strengthens an unsupported estimate |
| `flood` / `flood-relative` | belongs to a high-volume or repeated evidence pattern disproportionate to its belief-side contribution    |

These labels are relative to the belief model, state abstraction, aggregation rule, evidence weighting, and impairment model used in the experiment.

## Data

Raw external datasets are not redistributed in this repository.

The Mordor / OTRF Security Datasets source material should be obtained from the original dataset source, subject to its license and terms of use. This repository includes processed inputs and derived outputs used by the audit experiments where appropriate.

Raw data notes are provided in:

```text
data/raw/README.md
docs/datasets/mordor_notes.md
docs/data/
```

The processed Mordor-derived input used by the current bridge is:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

## Installation

Create and activate a Python environment. For example:

```bash
conda create -n alert-usefulness python=3.11
conda activate alert-usefulness
```

Install the project in editable mode:

```bash
pip install -e .
```

Install development/test dependencies if they are not already installed:

```bash
pip install pytest
```

Run the test suite:

```bash
pytest
```

## Running experiments

Run the synthetic baseline:

```bash
python experiments/exp01_synthetic_separation.py
```

Run the synthetic impairment sweep:

```bash
python experiments/exp02_impairment_sweep.py
```

Run the Mordor adapter / bridge experiment entry point:

```bash
python experiments/exp03_mordor_adapter.py
```

Additional Mordor-specific scripts are available in `scripts/`, including:

```text
scripts/extract_mordor_empire_mimikatz.py
scripts/validate_mordor_extracted_telemetry.py
scripts/run_mordor_belief_usefulness_experiment.py
scripts/run_mordor_impairment_experiment.py
scripts/run_mordor_belief_weight_sensitivity.py
scripts/run_mordor_event_aggregation_sensitivity.py
scripts/make_mordor_paper_figures.py
```

## Key outputs

Derived outputs are committed for inspection and paper review.

Important tables include:

```text
outputs/tables/mordor_belief_usefulness_summary.csv
outputs/tables/mordor_impairment_summary.csv
outputs/tables/mordor_belief_weight_sensitivity.csv
outputs/tables/mordor_event_aggregation_sensitivity.csv
outputs/tables/paper_summary_table.csv
outputs/tables/paper_summary_table.md
```

Important figures include:

```text
outputs/figures/mordor_delivery_vs_represented.png
outputs/figures/mordor_raw_vs_aggregated_usefulness.png
outputs/figures/mordor_weight_sensitivity.png
```

Experiment manifests are stored in:

```text
outputs/manifests/
```

Logs and local scratch outputs are ignored by git.

## Current paper-facing result summary

The current Mordor bridge shows that delivery volume and belief-side usefulness can separate.

In the raw healthy Mordor bridge, 6,026 delivered events produce a small number of useful belief updates under the selected scalar host-compromise abstraction, while most repeated events become redundant after belief saturation.

The impairment runs show that:

* delay can preserve delivery while creating stale updates;
* loss reduces delivery and represented delivery;
* noise can increase received volume while reducing represented evidence;
* duplication and alert flood increase volume without increasing represented source evidence;
* suppression removes selected source evidence;
* aggregation reduces repeated saturated updates but changes the audit object.

These findings should not be interpreted as operational SOC alert labels. They are audit-relative diagnostics under the declared model.

## Development notes

Design and interpretation notes are kept in:

```text
docs/design/
docs/results/
docs/data/
docs/datasets/
```

These notes document the evolution of the audit framework, Mordor bridge design, aggregation choices, belief saturation interpretation, and state-mapping limitations.

## Limitations

This repository is a research artifact, not an operational SOC tool.

Important limitations include:

* the belief model is intentionally simple;
* the main Mordor bridge uses a scalar host-compromise abstraction;
* usefulness labels depend on the declared state abstraction and evidence weights;
* aggregation changes the evidence unit being audited;
* the Mordor bridge is a bounded real-data bridge, not operational SOC validation;
* no human-subjects, analyst-performance, or cognitive-load study is performed here.

These limitations are intentional and are part of the paper’s scope.

## Citation

Citation metadata is provided in:

```text
CITATION.cff
```

Until the associated paper has a final publication record, please cite this repository as the experiment artifact for:

**Alert Usefulness Under Impaired Security Telemetry**

## License

This repository is released under the MIT License. External datasets are subject to their own licenses, terms of use, and citation requirements.
