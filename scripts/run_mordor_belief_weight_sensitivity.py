
"""Run Mordor belief-weight sensitivity checks.

This script compares the default ASTRA belief configuration against lower
belief-weight configurations for the healthy Mordor-derived telemetry run.

It does not change ASTRA's default model.
"""

from __future__ import annotations

from dataclasses import asdict, replace
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
    build_state_from_generated,
    load_mordor_processed_csv,
    mordor_to_generated_telemetry,
)
from scripts.run_mordor_paper_experiment import (
    belief_config_from_dict,
    load_config as load_paper_config,
    usefulness_config_from_dict,
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "tables"
    / "mordor_belief_weight_sensitivity.csv"
)


def belief_configs() -> list[tuple[str, BeliefConfig]]:
    """Return belief configurations for sensitivity comparison."""

    base = belief_config_from_dict(load_paper_config())

    return [
        (
            "default",
            base,
        ),
        (
            "half_weights",
            replace(base, score_weight=base.score_weight * 0.5),
        ),
        (
            "quarter_weights",
            replace(base, score_weight=base.score_weight * 0.25),
        ),
        (
            "low_weights",
            replace(base, score_weight=0.035),
        ),
    ]


def run_weight_sensitivity() -> pd.DataFrame:
    """Run healthy Mordor telemetry under several belief-weight settings."""

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

    records = []
    usefulness_config = usefulness_config_from_dict(load_paper_config())

    for config_name, belief_config in belief_configs():
        belief_df, event_updates_df = run_belief_update(
            state_df,
            delivered_df,
            belief_config,
        )

        diagnostics_df = diagnose_event_usefulness(
            state_df,
            delivered_df,
            event_updates_df,
            usefulness_config,
        )

        usefulness_summary = summarize_usefulness(
            generated_df,
            delivered_df,
            diagnostics_df,
        )
        belief_summary = summarize_belief(belief_df)

        config_dict = asdict(belief_config)

        saturated_updates = int(usefulness_summary["saturated_events"])

        records.append(
            {
                "scenario": SCENARIO,
                "impairment_mode": ImpairmentMode.HEALTHY.value,
                "belief_config": config_name,
                "auth_alert_weight": config_dict["auth_alert_weight"],
                "endpoint_alert_weight": config_dict["endpoint_alert_weight"],
                "network_alert_weight": config_dict["network_alert_weight"],
                "score_weight": config_dict["score_weight"],
                "generated_events": usefulness_summary["generated_events"],
                "delivered_events": usefulness_summary["delivered_events"],
                "useful_events": usefulness_summary["useful_events"],
                "redundant_events": usefulness_summary["redundant_events"],
                "misleading_events": usefulness_summary["misleading_events"],
                "useful_event_fraction": usefulness_summary["useful_event_fraction"],
                "redundant_event_fraction": usefulness_summary[
                    "redundant_event_fraction"
                ],
                "misleading_event_fraction": usefulness_summary[
                    "misleading_event_fraction"
                ],
                "mean_belief_delta": usefulness_summary["mean_belief_delta"],
                "mean_entropy_delta": usefulness_summary["mean_entropy_delta"],
                "mean_belief_error_delta": usefulness_summary[
                    "mean_belief_error_delta"
                ],
                "mean_belief_entropy": belief_summary["mean_belief_entropy"],
                "mean_belief_error": belief_summary["mean_belief_error"],
                "terminal_belief_entropy": belief_summary[
                    "terminal_belief_entropy"
                ],
                "terminal_belief_error": belief_summary["terminal_belief_error"],
                "saturated_updates": saturated_updates,
                "saturated_update_fraction": saturated_updates
                / len(event_updates_df),
            }
        )

    return pd.DataFrame.from_records(records)


def main() -> None:
    """Run sensitivity comparison and write output CSV."""

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    summary_df = run_weight_sensitivity()
    summary_df.to_csv(OUTPUT_PATH, index=False)

    print("ASTRA Mordor belief-weight sensitivity completed.")
    print(f"Summary written to: {OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print()
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()
