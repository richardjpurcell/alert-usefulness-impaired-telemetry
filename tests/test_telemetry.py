from astra.incident_state import IncidentStateConfig, generate_incident_state
from astra.telemetry import (
    TelemetryConfig,
    TelemetryEventType,
    generate_telemetry,
    summarize_telemetry,
    telemetry_signal_summary,
)


def test_generate_telemetry_columns():
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

    assert set(telemetry_df.columns) == {
        "event_id",
        "time",
        "host_id",
        "event_type",
        "event_score",
        "source_state",
        "is_true_signal",
    }


def test_generate_telemetry_one_event_per_state_row_when_probability_one():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=2,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=2,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    assert len(telemetry_df) == len(state_df)


def test_generate_telemetry_no_events_when_probability_zero():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=3,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=3,
            benign_event_probability=0.0,
            suspicious_event_probability=0.0,
            compromised_event_probability=0.0,
        ),
    )

    assert telemetry_df.empty


def test_event_types_are_known():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=4,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=4,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    known_types = {event_type.value for event_type in TelemetryEventType}

    assert set(telemetry_df["event_type"]).issubset(known_types)


def test_event_scores_are_between_zero_and_one():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=5,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=5,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    assert telemetry_df["event_score"].between(0.0, 1.0).all()


def test_summarize_telemetry():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=6,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=6,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    summary = summarize_telemetry(telemetry_df)

    assert "time" in summary.columns
    assert "total_events" in summary.columns
    assert len(summary) == 5
    assert summary["total_events"].sum() == len(telemetry_df)


def test_telemetry_signal_summary():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=7,
        )
    )

    telemetry_df = generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=7,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )

    summary = telemetry_signal_summary(telemetry_df)

    assert summary["total_events"] == len(telemetry_df)
    assert (
        summary["true_signal_events"] + summary["background_events"]
        == summary["total_events"]
    )