import pandas as pd
import pytest

from astra.datasets import (
    MORDOR_DEFAULT_COLUMN_MAP,
    MORDOR_SOURCE_DATASET,
    NORMALIZED_TELEMETRY_COLUMNS,
    load_generic_event_csv,
    load_mordor_event_csv,
    normalize_generic_event_table,
    normalize_mordor_event_table,
    require_normalized_telemetry_columns,
)


def _sample_mordor_like_event_table():
    return pd.DataFrame(
        [
            {
                "timestamp": "2020-05-02T02:56:00Z",
                "host": "WORKSTATION-001",
                "event_type": "process_creation",
                "severity": "high",
                "observed_state": "suspicious",
            },
            {
                "timestamp": "2020-05-02T02:57:00Z",
                "host": "DOMAIN-CONTROLLER",
                "event_type": "authentication",
                "severity": "medium",
                "observed_state": "compromised",
            },
        ]
    )


def _sample_event_table():
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "hostname": "host-001",
                "category": "process_creation",
                "risk_score": 0.8,
                "state": "suspicious",
            },
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "hostname": "host-002",
                "category": "authentication",
                "risk_score": 0.2,
                "state": "benign",
            },
        ]
    )


def _sample_column_map():
    return {
        "event_time": "timestamp",
        "host_id": "hostname",
        "event_type": "category",
        "severity": "risk_score",
        "observed_state": "state",
    }


def test_normalize_generic_event_table_has_expected_columns():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    )

    assert list(normalized.columns) == NORMALIZED_TELEMETRY_COLUMNS


def test_normalize_generic_event_table_assigns_event_ids():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    )

    assert list(normalized["event_id"]) == [0, 1]


def test_normalize_generic_event_table_maps_source_columns():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    )

    assert normalized.loc[0, "event_time"] == "2026-01-01T00:00:00Z"
    assert normalized.loc[0, "host_id"] == "host-001"
    assert normalized.loc[0, "event_type"] == "process_creation"
    assert normalized.loc[0, "severity"] == 0.8
    assert normalized.loc[0, "observed_state"] == "suspicious"


def test_normalize_generic_event_table_adds_dataset_metadata():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="mordor",
        scenario="empire-psexec",
    )

    assert set(normalized["source_dataset"]) == {"mordor"}
    assert set(normalized["scenario"]) == {"empire-psexec"}


def test_normalize_generic_event_table_rejects_missing_mappings():
    column_map = _sample_column_map()
    column_map.pop("observed_state")

    with pytest.raises(ValueError, match="column_map is missing required"):
        normalize_generic_event_table(
            _sample_event_table(),
            column_map=column_map,
            source_dataset="synthetic",
            scenario="unit-test",
        )


def test_normalize_generic_event_table_rejects_missing_source_columns():
    event_df = _sample_event_table().drop(columns=["risk_score"])

    with pytest.raises(ValueError, match="event_df is missing mapped source columns"):
        normalize_generic_event_table(
            event_df,
            column_map=_sample_column_map(),
            source_dataset="synthetic",
            scenario="unit-test",
        )


def test_require_normalized_telemetry_columns_accepts_valid_schema():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    )

    require_normalized_telemetry_columns(normalized)


def test_require_normalized_telemetry_columns_rejects_missing_columns():
    normalized = normalize_generic_event_table(
        _sample_event_table(),
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    ).drop(columns=["host_id"])

    with pytest.raises(ValueError, match="missing required columns"):
        require_normalized_telemetry_columns(normalized)


def test_load_generic_event_csv_loads_and_normalizes_csv(tmp_path):
    csv_path = tmp_path / "events.csv"

    _sample_event_table().to_csv(csv_path, index=False)

    normalized = load_generic_event_csv(
        csv_path,
        column_map=_sample_column_map(),
        source_dataset="synthetic",
        scenario="unit-test",
    )

    assert list(normalized.columns) == NORMALIZED_TELEMETRY_COLUMNS
    assert len(normalized) == 2
    assert normalized.loc[1, "host_id"] == "host-002"


def test_load_generic_event_csv_rejects_missing_file(tmp_path):
    missing_path = tmp_path / "missing.csv"

    with pytest.raises(FileNotFoundError, match="Event CSV not found"):
        load_generic_event_csv(
            missing_path,
            column_map=_sample_column_map(),
            source_dataset="synthetic",
            scenario="unit-test",
        )

def test_normalize_mordor_event_table_uses_default_schema():
    normalized = normalize_mordor_event_table(
        _sample_mordor_like_event_table(),
        scenario="apt29-test",
    )

    assert list(normalized.columns) == NORMALIZED_TELEMETRY_COLUMNS
    assert list(normalized["event_id"]) == [0, 1]
    assert set(normalized["source_dataset"]) == {MORDOR_SOURCE_DATASET}
    assert set(normalized["scenario"]) == {"apt29-test"}


def test_normalize_mordor_event_table_maps_default_columns():
    normalized = normalize_mordor_event_table(
        _sample_mordor_like_event_table(),
        scenario="apt29-test",
    )

    assert normalized.loc[0, "event_time"] == "2020-05-02T02:56:00Z"
    assert normalized.loc[0, "host_id"] == "WORKSTATION-001"
    assert normalized.loc[0, "event_type"] == "process_creation"
    assert normalized.loc[0, "severity"] == "high"
    assert normalized.loc[0, "observed_state"] == "suspicious"


def test_normalize_mordor_event_table_accepts_custom_column_map():
    event_df = pd.DataFrame(
        [
            {
                "TimeCreated": "2020-05-02T02:56:00Z",
                "Computer": "WORKSTATION-001",
                "EventID": "4688",
                "Level": "high",
                "State": "suspicious",
            }
        ]
    )

    normalized = normalize_mordor_event_table(
        event_df,
        scenario="windows-security-log-test",
        column_map={
            "event_time": "TimeCreated",
            "host_id": "Computer",
            "event_type": "EventID",
            "severity": "Level",
            "observed_state": "State",
        },
    )

    assert normalized.loc[0, "event_time"] == "2020-05-02T02:56:00Z"
    assert normalized.loc[0, "host_id"] == "WORKSTATION-001"
    assert normalized.loc[0, "event_type"] == "4688"
    assert normalized.loc[0, "severity"] == "high"
    assert normalized.loc[0, "observed_state"] == "suspicious"


def test_load_mordor_event_csv_loads_and_normalizes_csv(tmp_path):
    csv_path = tmp_path / "mordor_events.csv"

    _sample_mordor_like_event_table().to_csv(csv_path, index=False)

    normalized = load_mordor_event_csv(
        csv_path,
        scenario="apt29-test",
    )

    assert list(normalized.columns) == NORMALIZED_TELEMETRY_COLUMNS
    assert len(normalized) == 2
    assert set(normalized["source_dataset"]) == {MORDOR_SOURCE_DATASET}
    assert normalized.loc[1, "host_id"] == "DOMAIN-CONTROLLER"