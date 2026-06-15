import pandas as pd
import pytest

from scripts.run_mordor_impairment_experiment import (
    DEFAULT_SCENARIO,
    impairment_configs,
    mordor_to_generated_telemetry,
    run_mordor_impairment_summary,
    write_mordor_impairment_summary,
)


def _normalized_mordor_df():
    return pd.DataFrame(
        [
            {
                "event_id": "mordor_000000",
                "event_time": "2020-08-07T14:32:25.000Z",
                "host_id": "WORKSTATION5.theshire.local",
                "event_type": "powershell_pipeline",
                "severity": "medium",
                "observed_state": "suspicious",
                "source_dataset": "mordor",
                "scenario": DEFAULT_SCENARIO,
            },
            {
                "event_id": "mordor_000001",
                "event_time": "2020-08-07T14:32:30.000Z",
                "host_id": "MORDORDC.theshire.local",
                "event_type": "sysmon_process_access",
                "severity": "high",
                "observed_state": "compromised",
                "source_dataset": "mordor",
                "scenario": DEFAULT_SCENARIO,
            },
            {
                "event_id": "mordor_000002",
                "event_time": "2020-08-07T14:32:35.000Z",
                "host_id": "WORKSTATION6.theshire.local",
                "event_type": "other_security_event",
                "severity": "low",
                "observed_state": "benign",
                "source_dataset": "mordor",
                "scenario": DEFAULT_SCENARIO,
            },
        ]
    )


def _extracted_csv(path):
    pd.DataFrame(
        [
            {
                "timestamp": "2020-08-07T14:32:25.000Z",
                "host": "WORKSTATION5.theshire.local",
                "event_type": "powershell_pipeline",
                "severity": "medium",
                "observed_state": "suspicious",
            },
            {
                "timestamp": "2020-08-07T14:32:30.000Z",
                "host": "MORDORDC.theshire.local",
                "event_type": "sysmon_process_access",
                "severity": "high",
                "observed_state": "compromised",
            },
            {
                "timestamp": "2020-08-07T14:32:35.000Z",
                "host": "WORKSTATION6.theshire.local",
                "event_type": "other_security_event",
                "severity": "low",
                "observed_state": "benign",
            },
        ]
    ).to_csv(path, index=False)


def test_mordor_to_generated_telemetry_maps_schema():
    generated = mordor_to_generated_telemetry(_normalized_mordor_df())

    assert list(generated.columns) == [
        "event_id",
        "time",
        "host_id",
        "event_type",
        "event_score",
        "source_state",
        "is_true_signal",
    ]

    assert generated["time"].tolist() == [0, 5, 10]
    assert generated["event_score"].tolist() == [0.6, 0.9, 0.2]
    assert generated["source_state"].tolist() == [
        "suspicious",
        "compromised",
        "benign",
    ]
    assert generated["is_true_signal"].tolist() == [True, True, False]


def test_mordor_to_generated_telemetry_rejects_unknown_severity():
    df = _normalized_mordor_df()
    df.loc[0, "severity"] = "critical"

    with pytest.raises(ValueError, match="Unknown severity values"):
        mordor_to_generated_telemetry(df)


def test_mordor_to_generated_telemetry_rejects_unknown_observed_state():
    df = _normalized_mordor_df()
    df.loc[0, "observed_state"] = "unknown"

    with pytest.raises(ValueError, match="Unknown observed_state values"):
        mordor_to_generated_telemetry(df)


def test_impairment_configs_include_expected_modes():
    modes = [config.mode for config in impairment_configs(seed=7)]

    assert modes == [
        "healthy",
        "delay",
        "loss",
        "noise",
        "duplication",
        "alert_flood",
        "adversarial_suppression",
    ]


def test_run_mordor_impairment_summary(tmp_path):
    input_path = tmp_path / "empire_mimikatz_logonpasswords_events.csv"
    _extracted_csv(input_path)

    summary = run_mordor_impairment_summary(input_path=input_path, seed=7)

    assert summary["scenario"].unique().tolist() == [DEFAULT_SCENARIO]
    assert summary["impairment_mode"].tolist() == [
        "healthy",
        "delay",
        "loss",
        "noise",
        "duplication",
        "alert_flood",
        "adversarial_suppression",
    ]

    healthy = summary.loc[summary["impairment_mode"] == "healthy"].iloc[0]
    assert healthy["generated_events"] == 3
    assert healthy["delivered_events"] == 3
    assert healthy["delivery_rate"] == 1.0
    assert healthy["represented_delivery_rate"] == 1.0

    alert_flood = summary.loc[summary["impairment_mode"] == "alert_flood"].iloc[0]
    assert alert_flood["generated_events"] == 3
    assert alert_flood["synthetic_flood_events"] == 3
    assert alert_flood["delivered_events"] == 6


def test_write_mordor_impairment_summary(tmp_path):
    input_path = tmp_path / "empire_mimikatz_logonpasswords_events.csv"
    output_path = tmp_path / "mordor_impairment_summary.csv"
    _extracted_csv(input_path)

    written = write_mordor_impairment_summary(
        input_path=input_path,
        output_path=output_path,
        seed=7,
    )

    assert written == output_path
    assert output_path.exists()

    loaded = pd.read_csv(output_path)

    assert len(loaded) == 7
    assert "impairment_mode" in loaded.columns
    assert "delivery_rate" in loaded.columns