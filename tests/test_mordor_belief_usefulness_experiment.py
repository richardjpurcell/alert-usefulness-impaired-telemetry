
from pathlib import Path

import pandas as pd

from scripts.run_mordor_belief_usefulness_experiment import (
    build_state_from_generated,
    mordor_to_generated_telemetry,
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
