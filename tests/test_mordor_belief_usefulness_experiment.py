
from pathlib import Path

import pandas as pd

from scripts.run_mordor_belief_usefulness_experiment import (
    aggregate_generated_telemetry,
    build_state_from_generated,
    mordor_state_is_true_signal,
    mordor_to_generated_telemetry,
    normalize_mordor_observed_state,
    run_mordor_belief_usefulness_experiment,
)


def _sample_mordor_df():
    return pd.DataFrame(
        {
            "timestamp": [
                "2020-01-01T00:00:00Z",
                "2020-01-01T00:01:00Z",
                "2020-01-01T00:02:00Z",
                "2020-01-01T00:03:00Z",
            ],
            "host": ["host-a", "host-a", "host-b", "host-b"],
            "event_type": [
                "auth_alert",
                "endpoint_alert",
                "network_alert",
                "auth_alert",
            ],
            "severity": ["low", "high", "medium", "low"],
            "observed_state": [
                "benign",
                "compromised",
                "suspicious",
                "benign",
            ],
        }
    )


def test_mordor_to_generated_telemetry_schema():
    generated_df = mordor_to_generated_telemetry(_sample_mordor_df())

    assert list(generated_df.columns) == [
        "event_id",
        "time",
        "host_id",
        "event_type",
        "event_score",
        "source_state",
        "is_true_signal",
    ]

    assert len(generated_df) == 4
    assert generated_df["time"].tolist() == [0, 1, 2, 3]
    assert generated_df["event_score"].tolist() == [0.2, 0.9, 0.6, 0.2]
    assert generated_df["is_true_signal"].tolist() == [False, True, True, False]


def test_build_state_from_generated_extends_to_max_time():
    generated_df = mordor_to_generated_telemetry(_sample_mordor_df())
    state_df = build_state_from_generated(generated_df, max_time=6)

    assert set(state_df.columns) == {"time", "host_id", "state"}
    assert state_df["time"].max() == 6
    assert set(state_df["host_id"]) == {"host-a", "host-b"}
    assert not state_df["state"].isna().any()


def test_run_mordor_belief_usefulness_experiment_returns_summary_tables(tmp_path):
    input_path = Path(tmp_path) / "sample_mordor.csv"
    _sample_mordor_df().to_csv(input_path, index=False)

    summary_df, label_counts_df = run_mordor_belief_usefulness_experiment(input_path)

    assert not summary_df.empty
    assert set(summary_df["impairment_mode"]) == {
        "healthy",
        "delay",
        "loss",
        "noise",
        "duplication",
        "alert_flood",
        "adversarial_suppression",
    }

    assert {
        "scenario",
        "impairment_mode",
        "generated_events",
        "delivered_events",
        "represented_delivery_rate",
        "updated_events",
        "useful_events",
        "stale_events",
        "misleading_events",
        "flood_events",
        "belief_mean_belief_entropy",
        "event_update_updated_events",
    }.issubset(summary_df.columns)

    assert not label_counts_df.empty
    assert {"scenario", "impairment_mode", "usefulness_label", "count"}.issubset(
        label_counts_df.columns
    )

def test_aggregate_generated_telemetry_preserves_required_columns():
    from scripts.run_mordor_belief_usefulness_experiment import (
        aggregate_generated_telemetry,
    )

    generated_df = mordor_to_generated_telemetry(_sample_mordor_df())
    aggregated_df = aggregate_generated_telemetry(generated_df, window_steps=5)

    assert {
        "event_id",
        "time",
        "host_id",
        "event_type",
        "event_score",
        "source_state",
        "is_true_signal",
    }.issubset(aggregated_df.columns)

    assert {
        "source_event_count",
        "max_event_score",
        "mean_event_score",
        "aggregation_window_start",
        "aggregation_window_end",
    }.issubset(aggregated_df.columns)


def test_aggregate_generated_telemetry_reduces_repeated_records():
    from scripts.run_mordor_belief_usefulness_experiment import (
        aggregate_generated_telemetry,
    )

    generated_df = mordor_to_generated_telemetry(
        pd.DataFrame(
            {
                "timestamp": [
                    "2020-01-01T00:00:00Z",
                    "2020-01-01T00:01:00Z",
                    "2020-01-01T00:02:00Z",
                ],
                "host": ["host-a", "host-a", "host-a"],
                "event_type": ["endpoint_alert", "endpoint_alert", "endpoint_alert"],
                "severity": ["low", "medium", "high"],
                "observed_state": ["compromised", "compromised", "compromised"],
            }
        )
    )

    aggregated_df = aggregate_generated_telemetry(generated_df, window_steps=5)

    assert len(aggregated_df) == 1
    assert aggregated_df.loc[0, "source_event_count"] == 3


def test_aggregate_generated_telemetry_uses_max_event_score():
    from scripts.run_mordor_belief_usefulness_experiment import (
        aggregate_generated_telemetry,
    )

    generated_df = mordor_to_generated_telemetry(
        pd.DataFrame(
            {
                "timestamp": [
                    "2020-01-01T00:00:00Z",
                    "2020-01-01T00:01:00Z",
                ],
                "host": ["host-a", "host-a"],
                "event_type": ["endpoint_alert", "endpoint_alert"],
                "severity": ["low", "high"],
                "observed_state": ["compromised", "compromised"],
            }
        )
    )

    aggregated_df = aggregate_generated_telemetry(generated_df, window_steps=5)

    assert aggregated_df.loc[0, "event_score"] == 0.9
    assert aggregated_df.loc[0, "max_event_score"] == 0.9


def test_aggregate_generated_telemetry_is_deterministic():
    from scripts.run_mordor_belief_usefulness_experiment import (
        aggregate_generated_telemetry,
    )

    generated_df = mordor_to_generated_telemetry(_sample_mordor_df())

    first_df = aggregate_generated_telemetry(generated_df, window_steps=5)
    second_df = aggregate_generated_telemetry(generated_df, window_steps=5)

    pd.testing.assert_frame_equal(first_df, second_df)


def test_aggregate_generated_telemetry_rejects_nonpositive_window():
    from scripts.run_mordor_belief_usefulness_experiment import (
        aggregate_generated_telemetry,
    )

    generated_df = mordor_to_generated_telemetry(_sample_mordor_df())

    try:
        aggregate_generated_telemetry(generated_df, window_steps=0)
    except ValueError as exc:
        assert "window_steps must be positive" in str(exc)
    else:
        raise AssertionError("Expected ValueError")

def test_normalize_mordor_observed_state_known_values():

    assert normalize_mordor_observed_state("benign") == "benign"
    assert normalize_mordor_observed_state("suspicious") == "suspicious"
    assert normalize_mordor_observed_state("compromised") == "compromised"


def test_normalize_mordor_observed_state_handles_case_and_whitespace():

    assert normalize_mordor_observed_state(" Benign ") == "benign"
    assert normalize_mordor_observed_state(" SUSPICIOUS ") == "suspicious"
    assert normalize_mordor_observed_state(" Compromised ") == "compromised"


def test_normalize_mordor_observed_state_unknown_is_suspicious():

    assert normalize_mordor_observed_state("unknown") == "suspicious"
    assert normalize_mordor_observed_state("") == "suspicious"
    assert normalize_mordor_observed_state(None) == "suspicious"


def test_mordor_state_is_true_signal():

    assert mordor_state_is_true_signal("benign") is False
    assert mordor_state_is_true_signal("suspicious") is True
    assert mordor_state_is_true_signal("compromised") is True
    assert mordor_state_is_true_signal("unknown") is True


def test_mordor_to_generated_telemetry_uses_state_normalization():
    generated_df = mordor_to_generated_telemetry(
        pd.DataFrame(
            {
                "timestamp": [
                    "2020-01-01T00:00:00Z",
                    "2020-01-01T00:01:00Z",
                    "2020-01-01T00:02:00Z",
                ],
                "host": ["host-a", "host-a", "host-a"],
                "event_type": ["auth_alert", "auth_alert", "auth_alert"],
                "severity": ["low", "low", "low"],
                "observed_state": [" Benign ", "UNKNOWN", None],
            }
        )
    )

    assert generated_df["source_state"].tolist() == [
        "benign",
        "suspicious",
        "suspicious",
    ]
    assert generated_df["is_true_signal"].tolist() == [False, True, True]
