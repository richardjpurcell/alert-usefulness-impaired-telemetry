# Mordor paper experimental contract

This note records the exact paper-facing audit rules and experiment settings used by `scripts/run_mordor_paper_experiment.py`. The machine-readable configuration is `configs/mordor_paper_experiment.yaml`.

## Time and source mapping

The processed `Empire Mimikatz LogonPasswords` trace is sorted by source timestamp and represented at **one-second resolution**. Integer time is seconds elapsed from the first source event. The current processed input contains 6,026 source events.

Severity is mapped to a scalar event score:

| Severity | Score |
|---|---:|
| low | 0.20 |
| medium | 0.60 |
| high | 0.90 |

`observed_state` is normalized to `benign`, `suspicious`, or `compromised`; unknown or missing values map to `suspicious`. The binary audit target is

\[
x_t(h)=\mathbf 1[X_t(h)=\text{compromised}].
\]

For each host and second, the source-state table keeps the last event in source timestamp/event-id order, then forward-fills, backward-fills, and finally defaults to `benign` if no state is available.

## Belief model

For host \(h\), let \(p_{t,h}\) denote the maintained probability of compromise. The prior is

\[
p_0=0.05.
\]

Before processing events at each integer second, belief relaxes toward the prior:

\[
p^-_{t,h}=\operatorname{clip}\!\left(
 p_{t-1,h}+\lambda(p_0-p_{t-1,h}),
 p_{\min},p_{\max}
\right),
\]

with

\[
\lambda=0.00016749156927908793,\qquad p_{\min}=0.001,\qquad p_{\max}=0.999.
\]

The per-second decay is chosen to approximate the previous 1% per-minute relaxation after moving the Mordor bridge from minute to second resolution.

For a non-flood event \(e\), the proposed update is

\[
\delta_e=w_{\tau(e)}+\alpha s_e,
\]

where \(s_e\) is the event score and \(\alpha=0.25\). The paper bridge retains raw Mordor source event types rather than mapping them to the synthetic ASTRA `auth_alert`, `endpoint_alert`, and `network_alert` classes. Therefore the paper configuration explicitly sets

\[
w_{\mathrm{auth}}=w_{\mathrm{endpoint}}=w_{\mathrm{network}}=0,
\]

so the Mordor bridge uses the severity-score component only. The update is

\[
p^+_{t,h}=\operatorname{clip}(p^-_{t,h}+\delta_e,p_{\min},p_{\max}).
\]

Synthetic alert-flood events have \(\delta_e=0\): they add delivered volume but do not directly alter compromise belief.

Binary entropy is measured in bits:

\[
H(p)=-p\log_2 p-(1-p)\log_2(1-p).
\]

## Primary usefulness outcomes

Every delivered event or aggregated evidence unit receives exactly one primary outcome:

- `useful`
- `redundant`
- `misleading`

Let

\[
E^-_e=|p^-_e-x_e|,\qquad E^+_e=|p^+_e-x_e|,
\]

and

\[
\Delta E_e=E^+_e-E^-_e,\qquad \Delta H_e=H(p^+_e)-H(p^-_e).
\]

The classification order is:

\[
C_e=
\begin{cases}
\text{misleading}, & \Delta E_e\ge 0.01,\\
\text{useful}, & \Delta E_e\le -0.01,\\
\text{useful}, & \Delta H_e\le -0.005,\\
\text{redundant}, & \text{otherwise}.
\end{cases}
\]

The error criteria are evaluated first. Thus a materially wrong-direction update is not classified as useful merely because it reduces entropy.

## Independent diagnostic flags

The following flags do **not** replace the primary outcome and may overlap with it.

### Stale

An event is stale when

\[
t_e^{\mathrm{delivery}}-t_e^{\mathrm{generated}}>180\ \text{s}.
\]

### Saturated

An update is saturated when belief begins at a configured probability bound and receives same-direction evidence that cannot move it further. In the current positive-evidence Mordor bridge this is primarily

\[
p^-_e\ge p_{\max},\qquad \delta_e>0,\qquad p^+_e\ge p_{\max}.
\]

The symmetric lower-bound case is implemented for completeness. Zero-weight flood events are not marked saturated merely because belief is at a bound.

### Flood-relative

In the controlled paper experiment, a delivered event is flood-relative when it was injected by the `alert_flood` impairment. This is an experiment-side tag, not a proposed production flood detector.

## Impairment settings

The requested multi-level experiments use fixed seeds \(\{1,2,3,4,5,6,7,8,9,10\}\) and report mean and sample standard deviation.

| Mode | Tested levels | Other settings |
|---|---|---|
| Delay | 60 s, 240 s, 600 s | 30% of source events selected independently per seed |
| Loss | 10%, 30%, 50% drop probability | independent Bernoulli removal per source event |
| Alert flood | +0.5x, +1x, +2x source-event volume | flood scores uniform on [0.05, 0.25]; zero belief weight |

Secondary single-level checks use seed 1:

| Mode | Setting |
|---|---|
| Noise | false-positive rate 0.20; false-negative rate 0.20; synthetic score range [0.10, 0.45] |
| Duplication | duplicate probability 0.30 |
| Selective suppression | 0.50 suppression probability among source events whose mapped state is `compromised` |

## Aggregation

Healthy replay is compared with fixed windows of **5, 10, and 30 seconds**. Events are grouped by:

1. `host_id`
2. `aggregation_window_start`
3. `aggregation_window_end`
4. `event_type`
5. `source_state`

For each evidence unit:

- `event_score` is the maximum source-event score;
- `is_true_signal` is true if any represented source event is a true signal;
- `source_event_count` records the number of represented source events;
- the evidence-unit time is the aggregation-window start.

With second-resolution timing, the 6,026-event healthy trace becomes 338 units at 5 s, 251 units at 10 s, and 144 units at 30 s. This replaces the earlier minute-quantized experiment in which all three windows collapsed to the same 44 units.

## Reproduction outputs

Running

```bash
python scripts/run_mordor_paper_experiment.py
```

writes:

```text
outputs/tables/mordor_paper_runs.csv
outputs/tables/mordor_paper_summary.csv
outputs/tables/mordor_paper_aggregation.csv
outputs/manifests/mordor_paper_experiment.json
```

The manifest records the full configuration, input SHA-256, Git commit, and generated output paths.
