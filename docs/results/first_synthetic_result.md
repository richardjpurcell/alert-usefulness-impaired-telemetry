# First synthetic ASTRA result

## Claim

Security telemetry that arrives is not always useful.

## Experiment setup

Brief description of the six conditions:
Baseline, Delay, Loss, Noise, Suppression, Alert flood.

## Summary metrics

Reference:
outputs/tables/paper_summary_table.md

## Interpretation

Reference:
outputs/tables/interpretation_summary_table.md

## Figures

Reference:
outputs/figures/delivery_vs_usefulness.png
outputs/figures/belief_quality.png

## Main observations

1. Delay preserves delivery but increases staleness.
2. Loss reduces delivery but does not automatically reduce usefulness density.
3. Noise increases belief error.
4. Suppression raises entropy.
5. Alert flood inflates delivery while collapsing useful-event fraction.

## Paper-facing takeaway

The synthetic scaffold demonstrates that telemetry delivery, telemetry volume, and alert usefulness separate under impairment. ASTRA therefore evaluates security events not only by arrival, but by whether they improve the defender’s maintained belief about compromise.