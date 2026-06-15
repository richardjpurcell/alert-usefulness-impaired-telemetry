"""Validate extracted Mordor telemetry through ASTRA's dataset adapter.

This script assumes the local extractor has already produced:

    data/processed/empire_mimikatz_logonpasswords_events.csv

It loads that CSV through `load_mordor_event_csv` and prints a compact summary
of the normalized ASTRA telemetry dataframe.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from astra.datasets import load_mordor_event_csv


DEFAULT_INPUT_PATH = Path(
    "data/processed/empire_mimikatz_logonpasswords_events.csv"
)

DEFAULT_SCENARIO = "empire_mimikatz_logonpasswords"


def summarize_normalized_telemetry(input_path: str | Path) -> dict[str, object]:
    """Load extracted Mordor telemetry and return a compact summary."""

    telemetry_df = load_mordor_event_csv(
        input_path,
        scenario=DEFAULT_SCENARIO,
    )

    return {
        "rows": len(telemetry_df),
        "columns": list(telemetry_df.columns),
        "source_datasets": sorted(telemetry_df["source_dataset"].unique()),
        "scenarios": sorted(telemetry_df["scenario"].unique()),
        "hosts": sorted(telemetry_df["host_id"].unique()),
        "event_types": telemetry_df["event_type"].value_counts().to_dict(),
        "severity": telemetry_df["severity"].value_counts().to_dict(),
        "observed_state": telemetry_df["observed_state"].value_counts().to_dict(),
    }


def main() -> None:
    """Run validation from the command line."""

    parser = argparse.ArgumentParser(
        description="Validate extracted Mordor telemetry through ASTRA."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Path to extracted Mordor-like event CSV.",
    )

    args = parser.parse_args()

    summary = summarize_normalized_telemetry(args.input)

    print("Normalized Mordor telemetry summary")
    print("-----------------------------------")
    print(f"rows: {summary['rows']}")
    print(f"columns: {summary['columns']}")
    print(f"source_datasets: {summary['source_datasets']}")
    print(f"scenarios: {summary['scenarios']}")
    print(f"hosts: {summary['hosts']}")
    print(f"event_types: {summary['event_types']}")
    print(f"severity: {summary['severity']}")
    print(f"observed_state: {summary['observed_state']}")


if __name__ == "__main__":
    main()