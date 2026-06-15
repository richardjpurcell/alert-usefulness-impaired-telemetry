"""Run first impairment summaries over extracted Mordor telemetry.

This script bridges normalized Mordor telemetry into ASTRA's generated-telemetry
schema, then applies existing ASTRA impairment modes.

It intentionally stops at impairment summaries. Belief and usefulness diagnostics
come later.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from astra.datasets import load_mordor_event_csv
from astra.impairments import (
    ImpairmentConfig,
    ImpairmentMode,
    apply_impairment,
    summarize_impairment,
)


DEFAULT_INPUT_PATH = Path(
    "data/processed/empire_mimikatz_logonpasswords_events.csv"
)

DEFAULT_OUTPUT_PATH = Path(
    "outputs/tables/mordor_impairment_summary.csv"
)

DEFAULT_SCENARIO = "empire_mimikatz_logonpasswords"


SEVERITY_SCORE_MAP = {
    "low": 0.20,
    "medium": 0.60,
    "high": 0.90,
}


STATE_TRUE_SIGNAL_MAP = {
    "benign": False,
    "suspicious": True,
    "compromised": True,
}


def _time_to_step(event_time: pd.Series) -> pd.Series:
    """Convert event timestamps to integer steps from first observed timestamp."""

    parsed = pd.to_datetime(event_time, utc=True)
    first_time = parsed.min()

    return ((parsed - first_time).dt.total_seconds()).astype(int)


def mordor_to_generated_telemetry(normalized_df: pd.DataFrame) -> pd.DataFrame:
    """Convert normalized Mordor telemetry into ASTRA generated-telemetry schema."""

    required_columns = {
        "event_id",
        "event_time",
        "host_id",
        "event_type",
        "severity",
        "observed_state",
    }
    missing = required_columns - set(normalized_df.columns)

    if missing:
        raise ValueError(
            f"normalized_df is missing required columns: {sorted(missing)}"
        )

    generated = pd.DataFrame(
        {
            "event_id": normalized_df["event_id"].astype(str),
            "time": _time_to_step(normalized_df["event_time"]),
            "host_id": normalized_df["host_id"].astype(str),
            "event_type": normalized_df["event_type"].astype(str),
            "event_score": normalized_df["severity"].map(SEVERITY_SCORE_MAP),
            "source_state": normalized_df["observed_state"].astype(str),
            "is_true_signal": normalized_df["observed_state"].map(
                STATE_TRUE_SIGNAL_MAP
            ),
        }
    )

    if generated["event_score"].isna().any():
        unknown = sorted(
            normalized_df.loc[generated["event_score"].isna(), "severity"]
            .astype(str)
            .unique()
        )
        raise ValueError(f"Unknown severity values: {unknown}")

    if generated["is_true_signal"].isna().any():
        unknown = sorted(
            normalized_df.loc[generated["is_true_signal"].isna(), "observed_state"]
            .astype(str)
            .unique()
        )
        raise ValueError(f"Unknown observed_state values: {unknown}")

    generated["time"] = generated["time"].astype(int)
    generated["event_score"] = generated["event_score"].astype(float)
    generated["is_true_signal"] = generated["is_true_signal"].astype(bool)

    return generated.sort_values(["time", "host_id", "event_id"]).reset_index(
        drop=True
    )


def impairment_configs(seed: int = 42) -> list[ImpairmentConfig]:
    """Return the first Mordor impairment experiment set."""

    return [
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=seed),
        ImpairmentConfig(
            mode=ImpairmentMode.DELAY.value,
            seed=seed,
            delay_steps=5,
            affected_event_fraction=0.30,
        ),
        ImpairmentConfig(
            mode=ImpairmentMode.LOSS.value,
            seed=seed,
            drop_probability=0.30,
        ),
        ImpairmentConfig(
            mode=ImpairmentMode.NOISE.value,
            seed=seed,
            false_positive_rate=0.20,
            false_negative_rate=0.20,
        ),
        ImpairmentConfig(
            mode=ImpairmentMode.DUPLICATION.value,
            seed=seed,
            duplicate_probability=0.30,
        ),
        ImpairmentConfig(
            mode=ImpairmentMode.ALERT_FLOOD.value,
            seed=seed,
            flood_multiplier=1,
        ),
        ImpairmentConfig(
            mode=ImpairmentMode.ADVERSARIAL_SUPPRESSION.value,
            seed=seed,
            suppression_probability=0.50,
        ),
    ]


def run_mordor_impairment_summary(
    input_path: str | Path = DEFAULT_INPUT_PATH,
    seed: int = 42,
) -> pd.DataFrame:
    """Run impairment summaries over locally extracted Mordor telemetry."""

    normalized_df = load_mordor_event_csv(
        input_path,
        scenario=DEFAULT_SCENARIO,
    )
    generated_df = mordor_to_generated_telemetry(normalized_df)

    rows = []

    for config in impairment_configs(seed=seed):
        delivered_df = apply_impairment(generated_df, config)
        summary = summarize_impairment(generated_df, delivered_df)
        rows.append(
            {
                "scenario": DEFAULT_SCENARIO,
                "impairment_mode": config.mode,
                **summary,
            }
        )

    return pd.DataFrame(rows)


def write_mordor_impairment_summary(
    input_path: str | Path = DEFAULT_INPUT_PATH,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    seed: int = 42,
) -> Path:
    """Run and write Mordor impairment summary CSV."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary_df = run_mordor_impairment_summary(input_path=input_path, seed=seed)
    summary_df.to_csv(output_path, index=False)

    return output_path


def main() -> None:
    """Run from command line."""

    parser = argparse.ArgumentParser(
        description="Run first Mordor impairment summaries."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Path to extracted Mordor-like event CSV.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Path to write impairment summary CSV.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for impairment modes.",
    )

    args = parser.parse_args()

    output_path = write_mordor_impairment_summary(
        input_path=args.input,
        output_path=args.output,
        seed=args.seed,
    )

    print(output_path)


if __name__ == "__main__":
    main()