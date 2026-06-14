from astra.belief import (
    BeliefConfig,
    binary_entropy,
    run_belief_update,
    summarize_belief,
    summarize_event_updates,
)
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.incident_state import IncidentStateConfig, generate_incident_state
from astra.telemetry import TelemetryConfig, generate_telemetry


def _sample_state_and_delivered():
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
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
    )

    return state_df, delivered_df


def test_binary_entropy_bounds():
    assert binary_entropy(0.0) < 0.001
    assert binary_entropy(1.0) < 0.001
    assert 0.99 < binary_entropy(0.5) < 1.01


def test_run_belief_update_columns_and_shape():
    state_df, delivered_df = _sample_state_and_delivered()

    belief_df, event_updates_df = run_belief_update(
        state_df,
        delivered_df,
        BeliefConfig(prior_compromise_probability=0.05),
    )

    assert set(belief_df.columns) == {
        "time",
        "host_id",
        "belief_compromised",
        "belief_entropy",
        "true_state",
        "true_compromised",
        "belief_error",
    }

    assert len(belief_df) == len(state_df)
    assert len(event_updates_df) == len(delivered_df)


def test_beliefs_are_probabilities():
    state_df, delivered_df = _sample_state_and_delivered()

    belief_df, _ = run_belief_update(state_df, delivered_df)

    assert belief_df["belief_compromised"].between(0.0, 1.0).all()
    assert belief_df["belief_entropy"].between(0.0, 1.0).all()


def test_event_updates_have_expected_columns():
    state_df, delivered_df = _sample_state_and_delivered()

    _, event_updates_df = run_belief_update(state_df, delivered_df)

    assert set(event_updates_df.columns) == {
        "event_id",
        "delivery_time",
        "generated_time",
        "host_id",
        "event_type",
        "event_score",
        "is_synthetic_flood",
        "belief_before",
        "belief_after",
        "belief_delta",
        "entropy_before",
        "entropy_after",
        "entropy_delta",
    }


def test_alert_flood_events_can_reduce_belief():
    state_df, delivered_df = _sample_state_and_delivered()

    flooded_df = apply_impairment(
        delivered_df[
            [
                "event_id",
                "time",
                "host_id",
                "event_type",
                "event_score",
                "source_state",
                "is_true_signal",
            ]
        ],
        ImpairmentConfig(
            mode=ImpairmentMode.ALERT_FLOOD.value,
            seed=2,
            flood_multiplier=1,
        ),
    )

    _, event_updates_df = run_belief_update(
        state_df,
        flooded_df,
        BeliefConfig(synthetic_flood_penalty=0.04),
    )

    flood_updates = event_updates_df[event_updates_df["is_synthetic_flood"]]

    assert not flood_updates.empty
    assert (flood_updates["belief_delta"] <= 0).all()


def test_summarize_belief_returns_expected_keys():
    state_df, delivered_df = _sample_state_and_delivered()

    belief_df, _ = run_belief_update(state_df, delivered_df)
    summary = summarize_belief(belief_df)

    assert set(summary) == {
        "mean_belief_entropy",
        "mean_belief_error",
        "terminal_belief_entropy",
        "terminal_belief_error",
    }


def test_summarize_event_updates_returns_expected_keys():
    state_df, delivered_df = _sample_state_and_delivered()

    _, event_updates_df = run_belief_update(state_df, delivered_df)
    summary = summarize_event_updates(event_updates_df)

    assert set(summary) == {
        "updated_events",
        "mean_belief_delta",
        "mean_entropy_delta",
        "entropy_reducing_events",
        "entropy_increasing_events",
    }

    assert summary["updated_events"] == len(delivered_df)