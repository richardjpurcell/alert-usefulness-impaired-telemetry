from astra.belief import BeliefConfig, run_belief_update
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.incident_state import IncidentStateConfig, generate_incident_state
from astra.metrics import (
    UsefulnessConfig,
    UsefulnessLabel,
    diagnose_event_usefulness,
    summarize_usefulness,
    usefulness_label_counts,
)
from astra.telemetry import TelemetryConfig, generate_telemetry


def _pipeline(mode=ImpairmentMode.HEALTHY.value, impairment_config_kwargs=None):
    impairment_config_kwargs = impairment_config_kwargs or {}

    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=1,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=1,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=mode,
            seed=1,
            **impairment_config_kwargs,
        ),
    )

    _, event_updates_df = run_belief_update(
        state_df,
        delivered_df,
        BeliefConfig(),
    )

    diagnostics_df = diagnose_event_usefulness(
        state_df,
        delivered_df,
        event_updates_df,
        UsefulnessConfig(),
    )

    return state_df, telemetry_df, delivered_df, event_updates_df, diagnostics_df


def test_diagnose_event_usefulness_columns():
    _, _, delivered_df, event_updates_df, diagnostics_df = _pipeline()

    assert len(diagnostics_df) == len(event_updates_df)
    assert len(diagnostics_df) == len(delivered_df)

    assert set(diagnostics_df.columns) == {
        "event_id",
        "host_id",
        "generated_time",
        "delivery_time",
        "latency",
        "event_type",
        "event_score",
        "is_synthetic_flood",
        "true_state_at_generated_time",
        "true_state_at_delivery_time",
        "true_compromised_at_delivery_time",
        "belief_before",
        "belief_after",
        "belief_delta",
        "entropy_before",
        "entropy_after",
        "entropy_delta",
        "belief_error_before",
        "belief_error_after",
        "belief_error_delta",
        "usefulness_label",
    }


def test_usefulness_labels_are_known():
    *_, diagnostics_df = _pipeline()

    known_labels = {label.value for label in UsefulnessLabel}

    assert set(diagnostics_df["usefulness_label"]).issubset(known_labels)


def test_delay_can_create_stale_events():
    *_, diagnostics_df = _pipeline(
        mode=ImpairmentMode.DELAY.value,
        impairment_config_kwargs={
            "affected_event_fraction": 1.0,
            "delay_steps": 4,
        },
    )

    assert not diagnostics_df.empty
    assert (diagnostics_df["usefulness_label"] == UsefulnessLabel.STALE.value).all()

    assert not diagnostics_df.empty
    assert (diagnostics_df["usefulness_label"] == UsefulnessLabel.STALE.value).all()


def test_alert_flood_creates_flood_labels():
    *_, diagnostics_df = _pipeline(
        mode=ImpairmentMode.ALERT_FLOOD.value,
        impairment_config_kwargs={
            "flood_multiplier": 1,
        },
    )

    assert (diagnostics_df["usefulness_label"] == UsefulnessLabel.FLOOD.value).any()


def test_summarize_usefulness_returns_expected_keys():
    _, telemetry_df, delivered_df, _, diagnostics_df = _pipeline()

    summary = summarize_usefulness(telemetry_df, delivered_df, diagnostics_df)

    assert set(summary) == {
        "generated_events",
        "delivered_events",
        "synthetic_flood_events",
        "duplicate_events",
        "delayed_events",
        "missing_generated_events",
        "delivery_rate",
        "represented_delivery_rate",
        "updated_events",
        "useful_events",
        "stale_events",
        "redundant_events",
        "misleading_events",
        "uninformative_events",
        "flood_events",
        "useful_event_fraction",
        "stale_event_fraction",
        "redundant_event_fraction",
        "misleading_event_fraction",
        "mean_latency",
        "mean_belief_delta",
        "mean_entropy_delta",
        "mean_belief_error_delta",
    }


def test_usefulness_summary_counts_match_diagnostics():
    _, telemetry_df, delivered_df, _, diagnostics_df = _pipeline(
        mode=ImpairmentMode.ALERT_FLOOD.value,
        impairment_config_kwargs={
            "flood_multiplier": 1,
        },
    )

    summary = summarize_usefulness(telemetry_df, delivered_df, diagnostics_df)

    counted = (
        summary["useful_events"]
        + summary["stale_events"]
        + summary["redundant_events"]
        + summary["misleading_events"]
        + summary["uninformative_events"]
        + summary["flood_events"]
    )

    assert counted == len(diagnostics_df)


def test_usefulness_label_counts_returns_dataframe():
    *_, diagnostics_df = _pipeline()

    counts_df = usefulness_label_counts(diagnostics_df)

    assert set(counts_df.columns) == {"usefulness_label", "count"}
    assert counts_df["count"].sum() == len(diagnostics_df)