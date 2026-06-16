# Mordor state mapping impact check

This note records the impact check after adding explicit Mordor state-mapping
helpers.

## Context

The previous branch added a small, tested state-normalization surface to the
Mordor belief/usefulness bridge:

```text
normalize_mordor_observed_state(...)
mordor_state_is_true_signal(...)
```

Before this change, the bridge used inline dataframe logic:

```text
observed_state -> source_state
observed_state != benign -> is_true_signal
```

The helper branch did not intend to change the scientific model. Its purpose
was to make the current Mordor state abstraction explicit, centralized, and
tested.

## Purpose

This impact check should rerun the existing Mordor scripts and confirm whether
the explicit state helper changes the reported results.

The expected result is little or no change for the current Empire Mimikatz
LogonPasswords processed CSV, because the known state labels already align with
the earlier inline mapping.

## Scripts to rerun

Run the existing real-data scripts:

```bash
python scripts/run_mordor_belief_usefulness_experiment.py
python scripts/run_mordor_event_aggregation_sensitivity.py
```

Then run the test suite:

```bash
pytest
```

## Outputs to inspect

The scripts regenerate:

```text
outputs/tables/mordor_belief_usefulness_summary.csv
outputs/tables/mordor_belief_usefulness_label_counts.csv
outputs/tables/mordor_event_aggregation_sensitivity.csv
```

These CSV files are reproducible generated outputs and are not tracked.

## Expected comparison points

For the belief/usefulness summary, check the previously reported high-level
patterns:

| Impairment mode | Expected pattern |
|---|---|
| healthy | complete delivery; mostly redundant updates |
| delay | complete delivery with stale updates |
| loss | reduced delivery and represented delivery |
| noise | delivered volume may exceed generated volume while represented delivery falls |
| duplication | delivered volume inflates without increasing represented original evidence |
| alert_flood | delivered volume doubles with flood-labelled events |
| adversarial_suppression | small number of generated events missing |

For the aggregation sensitivity check, the previous result was:

| Mode | Window | Generated events | Source event count | Useful | Redundant | Misleading | Saturated update fraction |
|---|---:|---:|---:|---:|---:|---:|---:|
| raw | — | 6,026 | 6,026 | 7 | 5,986 | 33 | 0.993 |
| aggregated | 5 | 44 | 6,026 | 0 | 18 | 26 | 0.409 |
| aggregated | 10 | 44 | 6,026 | 0 | 18 | 26 | 0.409 |
| aggregated | 30 | 44 | 6,026 | 0 | 18 | 26 | 0.409 |

## Interpretation if results are unchanged

If the regenerated outputs match the earlier patterns, then the state-mapping
helper can be interpreted as a reproducibility and maintainability improvement,
not a modelling change.

That is the desired outcome for this branch.

The key point would be:

```text
The Mordor state abstraction is now explicit and tested, while the reported
belief/usefulness and aggregation results remain stable.
```

## Interpretation if results change

If the regenerated outputs change, inspect the processed CSV for state labels
that were previously handled differently by the inline mapping.

Likely cause:

```text
capitalization, whitespace, missing values, or unknown labels
```

Under the new helper:

```text
known states are normalized to lowercase;
missing or unknown states are mapped conservatively to suspicious;
true signal is defined as normalized_state != benign.
```

A change would not necessarily be wrong, but it should be documented as a
state-normalization effect rather than an impairment or belief-model effect.

## Recommended branch scope

This branch should remain small.

Recommended tracked files:

```text
docs/results/mordor_state_mapping_impact_check.md
```

If the rerun reveals changed outputs, update this note with the observed
differences. Do not track generated CSV files unless the project convention
changes.

## Main point

The purpose of this check is to protect interpretability:

```text
Before changing the belief model, confirm that making the Mordor state mapping
explicit did not silently alter the real-data bridge results.
```

This keeps ASTRA's real-data pipeline branch-by-branch, reproducible, and
honest about what changed.
