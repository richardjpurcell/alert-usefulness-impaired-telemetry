
"""Run Mordor-derived telemetry through ASTRA belief/usefulness diagnostics.

This is a first real-data bridge:

normalized Mordor telemetry
    -> generated-like ASTRA telemetry frame
    -> impairment
    -> defender belief update
    -> usefulness diagnostics
    -> summary table

The Mordor-to-ASTRA state mapping is an experimental abstraction, not
SOC-grade ground truth.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from astra.belief import (
    BeliefConfig,
    run_belief_update,
    summarize_belief,
    summarize_event_updates,
)
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.metrics import (
    UsefulnessConfig,
    diagnose_event_usefulness,
    summarize_usefulness,
    usefulness_label_counts,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "empire_mimikatz_logonpasswords_events.csv"
)

SUMMARY_OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_belief_usefulness_summary.csv"
)

LABEL_COUNTS_OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_belief_usefulness_label_counts.csv"
)

SCENARIO = "empire_mimikatz_logonpasswords"


SEVERITY_TO_SCORE = {
    "low": 0.20,
    "medium": 0.60,
    "high": 0.90,
}


def load_mordor_processed_csv(path: Path = INPUT_PATH) -> pd.DataFrame:
    """Load the processed Mordor telemetry CSV."""

    return pd.read_csv(path)


def mordor_to_generated_telemetry(mordor_df: pd.DataFrame) -> pd.DataFrame:
    """Map processed Mordor telemetry to ASTRA generated-telemetry schema."""

    required = {"timestamp", "host", "event_type", "severity", "observed_state"}
    missing = required - set(mordor_df.columns)

    if missing:
        raise ValueError(f"mordor_df is missing required columns: {sorted(missing)}")

    df = mordor_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values(["timestamp", "host", "event_type"]).reset_index(drop=True)

    first_timestamp = df["timestamp"].min()
    df["time"] = (
        (df["timestamp"] - first_timestamp).dt.total_seconds() // 60
    ).astype(int)

    df["event_id"] = [f"{SCENARIO}-{idx:06d}" for idx in range(len(df))]
    df["host_id"] = df["host"].astype(str)
    df["event_score"] = (
        df["severity"]
        .astype(str)
        .str.lower()
        .map(SEVERITY_TO_SCORE)
        .fillna(0.20)
        .astype(float)
    )
    df["source_state"] = df["observed_state"].astype(str)
    df["is_true_signal"] = df["source_state"] != "benign"

    return df[
        [
            "event_id",
            "time",
            "host_id",
            "event_type",
            "event_score",
            "source_state",
            "is_true_signal",
        ]
    ]


def aggregate_generated_telemetry(
    generated_df: pd.DataFrame,
    window_steps: int,
) -> pd.DataFrame:
    """Aggregate generated telemetry into host/window/event/state units."""

    if window_steps <= 0:
        raise ValueError("window_steps must be positive.")

    required = {
        "event_id",
        "time",
        "host_id",
        "event_type",
        "event_score",
        "source_state",
        "is_true_signal",
    }
    missing = required - set(generated_df.columns)

    if missing:
        raise ValueError(f"generated_df is missing required columns: {sorted(missing)}")

    df = generated_df.copy()
    df["time"] = df["time"].astype(int)
    df["aggregation_window_start"] = (df["time"] // window_steps) * window_steps
    df["aggregation_window_end"] = df["aggregation_window_start"] + window_steps - 1

    grouped = (
        df.groupby(
            [
                "host_id",
                "aggregation_window_start",
                "aggregation_window_end",
                "event_type",
                "source_state",
            ],
            sort=True,
        )
        .agg(
            event_score=("event_score", "max"),
            is_true_signal=("is_true_signal", "any"),
            source_event_count=("event_id", "count"),
            max_event_score=("event_score", "max"),
            mean_event_score=("event_score", "mean"),
        )
        .reset_index()
    )

    grouped["time"] = grouped["aggregation_window_start"].astype(int)
    grouped["event_id"] = [
        (
            f"agg-w{window_steps}-"
            f"{int(row.aggregation_window_start):06d}-"
            f"{row.host_id}-"
            f"{row.event_type}-"
            f"{row.source_state}-"
            f"{idx:06d}"
        )
        for idx, row in grouped.reset_index(drop=True).iterrows()
    ]

    return grouped[
        [
            "event_id",
            "time",
            "host_id",
            "event_type",
            "event_score",
            "source_state",
            "is_true_signal",
            "source_event_count",
            "max_event_score",
            "mean_event_score",
            "aggregation_window_start",
            "aggregation_window_end",
        ]
    ].reset_index(drop=True)


def build_state_from_generated(
    generated_df: pd.DataFrame,
    max_time: int | None = None,
) -> pd.DataFrame:
    """Build a host-by-time latent-state table from Mordor-derived telemetry.

    For this first real-data bridge, the observed_state field is used as the
    state abstraction. Missing host/time states are forward-filled, then
    backward-filled, then defaulted to benign.
    """

    required = {"time", "host_id", "source_state"}
    missing = required - set(generated_df.columns)

    if missing:
        raise ValueError(f"generated_df is missing required columns: {sorted(missing)}")

    max_time = int(max_time if max_time is not None else generated_df["time"].max())
    hosts = sorted(generated_df["host_id"].astype(str).unique())
    times = list(range(0, max_time + 1))

    observations = (
        generated_df.sort_values(["time", "host_id"])
        .drop_duplicates(["time", "host_id"], keep="last")
        [["time", "host_id", "source_state"]]
        .rename(columns={"source_state": "state"})
    )

    grid = pd.MultiIndex.from_product(
        [times, hosts],
        names=["time", "host_id"],
    ).to_frame(index=False)

    state_df = grid.merge(observations, on=["time", "host_id"], how="left")
    state_df["state"] = (
        state_df.groupby("host_id")["state"]
        .ffill()
        .bfill()
        .fillna("benign")
    )

    return state_df[["time", "host_id", "state"]]


def impairment_configs() -> list[tuple[str, ImpairmentConfig]]:
    """Return the impairment settings used for the first Mordor bridge."""

    return [
        (
            ImpairmentMode.HEALTHY.value,
            ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
        ),
        (
            ImpairmentMode.DELAY.value,
            ImpairmentConfig(
                mode=ImpairmentMode.DELAY.value,
                seed=1,
                delay_steps=4,
                affected_event_fraction=0.3,
            ),
        ),
        (
            ImpairmentMode.LOSS.value,
            ImpairmentConfig(
                mode=ImpairmentMode.LOSS.value,
                seed=1,
                drop_probability=0.3,
            ),
        ),
        (
            ImpairmentMode.NOISE.value,
            ImpairmentConfig(
                mode=ImpairmentMode.NOISE.value,
                seed=1,
                false_positive_rate=0.2,
                false_negative_rate=0.2,
            ),
        ),
        (
            ImpairmentMode.DUPLICATION.value,
            ImpairmentConfig(
                mode=ImpairmentMode.DUPLICATION.value,
                seed=1,
                duplicate_probability=0.3,
            ),
        ),
        (
            ImpairmentMode.ALERT_FLOOD.value,
            ImpairmentConfig(
                mode=ImpairmentMode.ALERT_FLOOD.value,
                seed=1,
                flood_multiplier=1,
            ),
        ),
        (
            ImpairmentMode.ADVERSARIAL_SUPPRESSION.value,
            ImpairmentConfig(
                mode=ImpairmentMode.ADVERSARIAL_SUPPRESSION.value,
                seed=1,
                suppression_probability=0.5,
                suppress_compromised_host_events=True,
            ),
        ),
    ]


def run_one_mode(
    generated_df: pd.DataFrame,
    impairment_mode: str,
    impairment_config: ImpairmentConfig,
) -> dict[str, int | float | str]:
    """Run one impairment mode through belief/usefulness diagnostics."""

    delivered_df = apply_impairment(generated_df, impairment_config)

    max_state_time = int(
        max(
            generated_df["time"].max(),
            delivered_df["delivery_time"].max()
            if "delivery_time" in delivered_df.columns
            else delivered_df["time"].max(),
        )
    )

    state_df = build_state_from_generated(generated_df, max_time=max_state_time)

    belief_df, event_updates_df = run_belief_update(
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

    usefulness_summary = summarize_usefulness(
        generated_df,
        delivered_df,
        diagnostics_df,
    )
    belief_summary = summarize_belief(belief_df)
    event_update_summary = summarize_event_updates(event_updates_df)

    return {
        "scenario": SCENARIO,
        "impairment_mode": impairment_mode,
        **usefulness_summary,
        **{f"belief_{key}": value for key, value in belief_summary.items()},
        **{
            f"event_update_{key}": value
            for key, value in event_update_summary.items()
        },
    }


def run_mordor_belief_usefulness_experiment(
    input_path: Path = INPUT_PATH,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run all Mordor impairment modes and return summary tables."""

    mordor_df = load_mordor_processed_csv(input_path)
    generated_df = mordor_to_generated_telemetry(mordor_df)

    summary_records = []
    label_count_records = []

    for impairment_mode, config in impairment_configs():
        delivered_df = apply_impairment(generated_df, config)

        max_state_time = int(
            max(
                generated_df["time"].max(),
                delivered_df["delivery_time"].max()
                if "delivery_time" in delivered_df.columns
                else delivered_df["time"].max(),
            )
        )

        state_df = build_state_from_generated(generated_df, max_time=max_state_time)

        belief_df, event_updates_df = run_belief_update(
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

        usefulness_summary = summarize_usefulness(
            generated_df,
            delivered_df,
            diagnostics_df,
        )
        belief_summary = summarize_belief(belief_df)
        event_update_summary = summarize_event_updates(event_updates_df)

        summary_records.append(
            {
                "scenario": SCENARIO,
                "impairment_mode": impairment_mode,
                **usefulness_summary,
                **{f"belief_{key}": value for key, value in belief_summary.items()},
                **{
                    f"event_update_{key}": value
                    for key, value in event_update_summary.items()
                },
            }
        )

        counts_df = usefulness_label_counts(diagnostics_df)
        for _, row in counts_df.iterrows():
            label_count_records.append(
                {
                    "scenario": SCENARIO,
                    "impairment_mode": impairment_mode,
                    "usefulness_label": row["usefulness_label"],
                    "count": int(row["count"]),
                }
            )

    return (
        pd.DataFrame.from_records(summary_records),
        pd.DataFrame.from_records(label_count_records),
    )


def main() -> None:
    """Run the Mordor belief/usefulness bridge and write CSV outputs."""

    SUMMARY_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    summary_df, label_counts_df = run_mordor_belief_usefulness_experiment()

    summary_df.to_csv(SUMMARY_OUTPUT_PATH, index=False)
    label_counts_df.to_csv(LABEL_COUNTS_OUTPUT_PATH, index=False)

    print("ASTRA Mordor belief/usefulness experiment completed.")
    print(f"Summary written to: {SUMMARY_OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(
        "Label counts written to: "
        f"{LABEL_COUNTS_OUTPUT_PATH.relative_to(PROJECT_ROOT)}"
    )


if __name__ == "__main__":
    main()
