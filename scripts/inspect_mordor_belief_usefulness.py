
"""Inspect first Mordor belief/usefulness diagnostics.

This script explains why the initial Mordor healthy run produces mostly
redundant updates, with a small number of useful and misleading updates.

It is diagnostic only: it does not change ASTRA's belief or usefulness model.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from astra.belief import BeliefConfig, run_belief_update
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.metrics import UsefulnessConfig, diagnose_event_usefulness

from scripts.run_mordor_belief_usefulness_experiment import (
    PROJECT_ROOT,
    SCENARIO,
    build_state_from_generated,
    load_mordor_processed_csv,
    mordor_to_generated_telemetry,
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_healthy_usefulness_diagnostic_samples.csv"
)

SUMMARY_OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_healthy_usefulness_interpretation.csv"
)


def run_healthy_diagnostics() -> pd.DataFrame:
    """Regenerate healthy Mordor event-level usefulness diagnostics."""

    mordor_df = load_mordor_processed_csv()
    generated_df = mordor_to_generated_telemetry(mordor_df)

    delivered_df = apply_impairment(
        generated_df,
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
    )

    state_df = build_state_from_generated(
        generated_df,
        max_time=int(generated_df["time"].max()),
    )

    _, event_updates_df = run_belief_update(
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

    return diagnostics_df


def summarize_by_label(diagnostics_df: pd.DataFrame) -> pd.DataFrame:
    """Summarize diagnostic magnitudes by usefulness label."""

    return (
        diagnostics_df.groupby("usefulness_label")
        .agg(
            events=("event_id", "count"),
            mean_event_score=("event_score", "mean"),
            mean_belief_delta=("belief_delta", "mean"),
            mean_entropy_delta=("entropy_delta", "mean"),
            mean_belief_error_delta=("belief_error_delta", "mean"),
            min_belief_error_delta=("belief_error_delta", "min"),
            max_belief_error_delta=("belief_error_delta", "max"),
            mean_belief_before=("belief_before", "mean"),
            mean_belief_after=("belief_after", "mean"),
        )
        .reset_index()
        .sort_values("usefulness_label")
    )


def sample_diagnostics(diagnostics_df: pd.DataFrame) -> pd.DataFrame:
    """Return small labelled samples for manual inspection."""

    parts = []

    for label in sorted(diagnostics_df["usefulness_label"].unique()):
        subset = diagnostics_df[diagnostics_df["usefulness_label"] == label]
        parts.append(
            subset.sort_values(
                ["belief_error_delta", "entropy_delta", "event_id"],
                ascending=[True, True, True],
            ).head(10)
        )

    return pd.concat(parts, ignore_index=True)


def main() -> None:
    """Write diagnostic interpretation tables."""

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    diagnostics_df = run_healthy_diagnostics()
    summary_df = summarize_by_label(diagnostics_df)
    samples_df = sample_diagnostics(diagnostics_df)

    summary_df.insert(0, "scenario", SCENARIO)
    samples_df.insert(0, "scenario", SCENARIO)

    summary_df.to_csv(SUMMARY_OUTPUT_PATH, index=False)
    samples_df.to_csv(OUTPUT_PATH, index=False)

    print("ASTRA Mordor healthy usefulness inspection completed.")
    print(f"Summary written to: {SUMMARY_OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Samples written to: {OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print()
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()
