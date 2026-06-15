"""Dataset adapter utilities.

Defines normalized schemas for bringing external security telemetry datasets
into ASTRA.

The goal is to keep dataset-specific parsing separate from ASTRA's impairment,
belief, metric, and reporting pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


NORMALIZED_TELEMETRY_COLUMNS = [
    "event_id",
    "event_time",
    "host_id",
    "event_type",
    "severity",
    "observed_state",
    "source_dataset",
    "scenario",
]

MORDOR_DEFAULT_COLUMN_MAP = {
    "event_time": "timestamp",
    "host_id": "host",
    "event_type": "event_type",
    "severity": "severity",
    "observed_state": "observed_state",
}


MORDOR_SOURCE_DATASET = "mordor"


def require_normalized_telemetry_columns(
    telemetry_df: pd.DataFrame,
    name: str = "telemetry_df",
) -> None:
    """Validate that a dataframe satisfies the normalized telemetry schema."""

    missing = set(NORMALIZED_TELEMETRY_COLUMNS) - set(telemetry_df.columns)

    if missing:
        raise ValueError(f"{name} is missing required columns: {sorted(missing)}")


def normalize_generic_event_table(
    event_df: pd.DataFrame,
    column_map: dict[str, str],
    source_dataset: str,
    scenario: str,
) -> pd.DataFrame:
    """Normalize a generic event table into ASTRA's telemetry schema.

    Parameters
    ----------
    event_df:
        Source event table.
    column_map:
        Mapping from normalized ASTRA column names to source dataframe columns.
        For example: {"event_time": "timestamp", "host_id": "hostname"}.
    source_dataset:
        Dataset label, such as "synthetic", "mordor", or "otrf".
    scenario:
        Scenario label.

    Returns
    -------
    pandas.DataFrame
        Normalized telemetry table.
    """

    required_mapped_columns = {
        "event_time",
        "host_id",
        "event_type",
        "severity",
        "observed_state",
    }

    missing_mappings = required_mapped_columns - set(column_map)

    if missing_mappings:
        raise ValueError(
            "column_map is missing required normalized columns: "
            f"{sorted(missing_mappings)}"
        )

    missing_source_columns = set(column_map.values()) - set(event_df.columns)

    if missing_source_columns:
        raise ValueError(
            "event_df is missing mapped source columns: "
            f"{sorted(missing_source_columns)}"
        )

    normalized = pd.DataFrame()

    normalized["event_id"] = range(len(event_df))

    for normalized_column, source_column in column_map.items():
        normalized[normalized_column] = event_df[source_column].values

    normalized["source_dataset"] = source_dataset
    normalized["scenario"] = scenario

    normalized = normalized[NORMALIZED_TELEMETRY_COLUMNS]

    require_normalized_telemetry_columns(normalized, name="normalized")

    return normalized


def load_generic_event_csv(
    csv_path: str | Path,
    column_map: dict[str, str],
    source_dataset: str,
    scenario: str,
) -> pd.DataFrame:
    """Load and normalize a generic event CSV."""

    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(f"Event CSV not found: {csv_path}")

    event_df = pd.read_csv(csv_path)

    return normalize_generic_event_table(
        event_df,
        column_map=column_map,
        source_dataset=source_dataset,
        scenario=scenario,
    )

def normalize_mordor_event_table(
    event_df: pd.DataFrame,
    scenario: str,
    column_map: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Normalize a Mordor/OTRF-style event table into ASTRA's telemetry schema.

    This first-pass adapter expects a simplified, extracted Mordor-like table.
    Full JSON parsing and ATT&CK metadata handling are intentionally left to a
    later branch.
    """

    return normalize_generic_event_table(
        event_df,
        column_map=column_map or MORDOR_DEFAULT_COLUMN_MAP,
        source_dataset=MORDOR_SOURCE_DATASET,
        scenario=scenario,
    )


def load_mordor_event_csv(
    csv_path: str | Path,
    scenario: str,
    column_map: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Load and normalize a Mordor/OTRF-style event CSV."""

    return load_generic_event_csv(
        csv_path,
        column_map=column_map or MORDOR_DEFAULT_COLUMN_MAP,
        source_dataset=MORDOR_SOURCE_DATASET,
        scenario=scenario,
    )