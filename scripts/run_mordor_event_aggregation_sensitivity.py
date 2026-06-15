"""Run Mordor event-aggregation sensitivity checks.

This script compares raw Mordor-derived telemetry with aggregated telemetry
before impairment and belief update.

It does not change ASTRA's default pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from astra.belief import BeliefConfig, run_belief_update, summarize_belief
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.metrics import (
    UsefulnessConfig,
    diagnose_event_usefulness,
    summarize_usefulness,
)

from scripts.run_mordor_belief_usefulness_experiment import (
    PROJECT_ROOT,
    SCENARIO,
    aggregate_generated_telemetry,
    build_state_from_generated,
    load_mordor_processed_csv,
    mordor_to_generated_telemetry,
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_event_aggregation_sensitivity.csv"
)


def _saturated_updates(event_updates_df: pd.DataFrame) -> int:
    """Count updates that start and end at the configured saturation value."""

    return int(
        (
            (event_updates_df["belief_before"] >= BeliefConfig().max_probability)
            & (event_updates_df["belief_after"] >= BeliefConfig().max_probability)
        ).sum()
    )


def run_one(
    generated_df: pd.DataFrame,
    aggregation_mode: str,
    aggregation_window_steps: int | None,
) -> dict[str, int | float | str | None]:
    """Run one healthy aggregation sensitivity condition."""

    delivered_df = apply_impairment(
        generated_df,
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
    )

    state_df = build_state_from_generated(
        generated_df,
        max_time=int(generated_df["time"].max()),
    )

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

    saturated_updates = _saturated_updates(event_updates_df)

    source_event_count = (
        int(generated_df["source_event_count"].sum())
        if "source_event_count" in generated_df.columns
        else int(len(generated_df))
    )

    return {
        "scenario": SCENARIO,
        "impairment_mode": ImpairmentMode.HEALTHY.value,
        "aggregation_mode": aggregation_mode,
        "aggregation_window_steps": aggregation_window_steps,
        "generated_events": usefulness_summary["generated_events"],
        "delivered_events": usefulness_summary["delivered_events"],
        "source_event_count": source_event_count,
        "useful_events": usefulness_summary["useful_events"],
        "redundant_events": usefulness_summary["redundant_events"],
        "misleading_events": usefulness_summary["misleading_events"],
        "uninformative_events": usefulness_summary["uninformative_events"],
        "flood_events": usefulness_summary["flood_events"],
        "useful_event_fraction": usefulness_summary["useful_event_fraction"],
        "redundant_event_fraction": usefulness_summary["redundant_event_fraction"],
        "mean_belief_delta": usefulness_summary["mean_belief_delta"],
        "mean_entropy_delta": usefulness_summary["mean_entropy_delta"],
        "mean_belief_error_delta": usefulness_summary["mean_belief_error_delta"],
        "belief_mean_belief_entropy": belief_summary["mean_belief_entropy"],
        "belief_mean_belief_error": belief_summary["mean_belief_error"],
        "saturated_updates": saturated_updates,
        "saturated_update_fraction": saturated_updates / len(event_updates_df),
    }


def run_event_aggregation_sensitivity() -> pd.DataFrame:
    """Compare raw and aggregated Mordor healthy-mode diagnostics."""

    mordor_df = load_mordor_processed_csv()
    raw_generated_df = mordor_to_generated_telemetry(mordor_df)

    records = [
        run_one(
            raw_generated_df,
            aggregation_mode="raw",
            aggregation_window_steps=None,
        )
    ]

    for window_steps in [5, 10, 30]:
        aggregated_df = aggregate_generated_telemetry(
            raw_generated_df,
            window_steps=window_steps,
        )
        records.append(
            run_one(
                aggregated_df,
                aggregation_mode="aggregated",
                aggregation_window_steps=window_steps,
            )
        )

    return pd.DataFrame.from_records(records)


def main() -> None:
    """Run event aggregation sensitivity and write output CSV."""

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    summary_df = run_event_aggregation_sensitivity()
    summary_df.to_csv(OUTPUT_PATH, index=False)

    print("ASTRA Mordor event-aggregation sensitivity completed.")
    print(f"Summary written to: {OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print()
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()