"""Run the canonical paper-facing Mordor reproducibility experiment.

The experiment is configured by ``configs/mordor_paper_experiment.yaml`` and
produces:

- one row per randomized run;
- mean and sample standard deviation by impairment level;
- a deterministic aggregation sensitivity table; and
- a manifest containing the exact configuration, input SHA-256, and Git commit.

The primary usefulness outcome is one of useful/redundant/misleading.  Stale,
saturated, and flood-relative are independent diagnostic flags.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import gc
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from astra.belief import BeliefConfig, run_belief_update, summarize_belief
from astra.impairments import ImpairmentConfig, ImpairmentMode, apply_impairment
from astra.metrics import UsefulnessConfig, diagnose_event_usefulness, summarize_usefulness
from scripts.run_mordor_belief_usefulness_experiment import (
    INPUT_PATH,
    PROJECT_ROOT,
    SCENARIO,
    aggregate_generated_telemetry,
    build_state_from_generated,
    load_mordor_processed_csv,
    mordor_to_generated_telemetry,
)

CONFIG_PATH = PROJECT_ROOT / "configs" / "mordor_paper_experiment.yaml"
RUNS_OUTPUT_PATH = PROJECT_ROOT / "outputs" / "tables" / "mordor_paper_runs.csv"
SUMMARY_OUTPUT_PATH = PROJECT_ROOT / "outputs" / "tables" / "mordor_paper_summary.csv"
AGGREGATION_OUTPUT_PATH = (
    PROJECT_ROOT / "outputs" / "tables" / "mordor_paper_aggregation.csv"
)
MANIFEST_OUTPUT_PATH = (
    PROJECT_ROOT / "outputs" / "manifests" / "mordor_paper_experiment.json"
)


def load_config(path: str | Path = CONFIG_PATH) -> dict[str, Any]:
    """Load the canonical experiment configuration."""

    with Path(path).open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    if not isinstance(config, dict):
        raise ValueError("Paper experiment configuration must be a mapping.")

    return config


def belief_config_from_dict(config: dict[str, Any]) -> BeliefConfig:
    """Construct the exact paper-facing belief configuration."""

    belief = config["belief"]
    return BeliefConfig(
        prior_compromise_probability=float(belief["prior_compromise_probability"]),
        auth_alert_weight=float(belief["auth_alert_weight"]),
        endpoint_alert_weight=float(belief["endpoint_alert_weight"]),
        network_alert_weight=float(belief["network_alert_weight"]),
        score_weight=float(belief["score_weight"]),
        synthetic_flood_penalty=float(belief["synthetic_flood_penalty"]),
        decay_to_prior=float(belief["decay_to_prior"]),
        min_probability=float(belief["min_probability"]),
        max_probability=float(belief["max_probability"]),
    )


def usefulness_config_from_dict(config: dict[str, Any]) -> UsefulnessConfig:
    """Construct the exact paper-facing usefulness configuration."""

    usefulness = config["usefulness"]
    return UsefulnessConfig(
        stale_after_steps=int(usefulness["stale_after_seconds"]),
        min_abs_entropy_delta=float(usefulness["min_abs_entropy_delta"]),
        min_error_improvement=float(usefulness["min_error_improvement"]),
        min_error_worsening=float(usefulness["min_error_worsening"]),
    )


def _run_pipeline(
    generated_df: pd.DataFrame,
    impairment_config: ImpairmentConfig,
    belief_config: BeliefConfig,
    usefulness_config: UsefulnessConfig,
) -> dict[str, int | float]:
    """Run one generated stream through impairment, belief, and diagnostics."""

    delivered_df = apply_impairment(generated_df, impairment_config)
    max_state_time = int(
        max(
            generated_df["time"].max(),
            delivered_df["delivery_time"].max()
            if not delivered_df.empty
            else generated_df["time"].max(),
        )
    )
    state_df = build_state_from_generated(generated_df, max_time=max_state_time)
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

    return {
        **usefulness_summary,
        **{f"belief_{key}": value for key, value in belief_summary.items()},
    }


def _condition_specs(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the randomized impairment conditions from the YAML config."""

    imp = config["impairments"]
    specs: list[dict[str, Any]] = []

    for delay_seconds in imp["delay"]["delay_seconds"]:
        specs.append(
            {
                "impairment_mode": ImpairmentMode.DELAY.value,
                "level_label": f"delay_{int(delay_seconds)}s",
                "parameter_name": "delay_seconds",
                "parameter_value": float(delay_seconds),
                "repeat_across_seeds": True,
                "kwargs": {
                    "delay_steps": int(delay_seconds),
                    "affected_event_fraction": float(
                        imp["delay"]["affected_event_fraction"]
                    ),
                },
            }
        )

    for probability in imp["loss"]["drop_probability"]:
        specs.append(
            {
                "impairment_mode": ImpairmentMode.LOSS.value,
                "level_label": f"loss_{float(probability):.2f}",
                "parameter_name": "drop_probability",
                "parameter_value": float(probability),
                "repeat_across_seeds": True,
                "kwargs": {"drop_probability": float(probability)},
            }
        )

    for multiplier in imp["alert_flood"]["flood_multiplier"]:
        specs.append(
            {
                "impairment_mode": ImpairmentMode.ALERT_FLOOD.value,
                "level_label": f"flood_{float(multiplier):g}x",
                "parameter_name": "additional_flood_multiplier",
                "parameter_value": float(multiplier),
                "repeat_across_seeds": True,
                "kwargs": {"flood_multiplier": float(multiplier)},
            }
        )

    noise = imp["noise"]
    specs.append(
        {
            "impairment_mode": ImpairmentMode.NOISE.value,
            "level_label": "noise_fp0.20_fn0.20",
            "parameter_name": "false_positive_false_negative_rate",
            "parameter_value": float(noise["false_positive_rate"]),
            "repeat_across_seeds": False,
            "kwargs": {
                "false_positive_rate": float(noise["false_positive_rate"]),
                "false_negative_rate": float(noise["false_negative_rate"]),
                "noise_score_range": tuple(float(v) for v in noise["noise_score_range"]),
            },
        }
    )

    duplication = imp["duplication"]
    specs.append(
        {
            "impairment_mode": ImpairmentMode.DUPLICATION.value,
            "level_label": "duplication_0.30",
            "parameter_name": "duplicate_probability",
            "parameter_value": float(duplication["duplicate_probability"]),
            "repeat_across_seeds": False,
            "kwargs": {
                "duplicate_probability": float(duplication["duplicate_probability"])
            },
        }
    )

    suppression = imp["adversarial_suppression"]
    specs.append(
        {
            "impairment_mode": ImpairmentMode.ADVERSARIAL_SUPPRESSION.value,
            "level_label": "suppression_0.50",
            "parameter_name": "suppression_probability",
            "parameter_value": float(suppression["suppression_probability"]),
            "repeat_across_seeds": False,
            "kwargs": {
                "suppression_probability": float(
                    suppression["suppression_probability"]
                ),
                "suppress_compromised_host_events": bool(
                    suppression["suppress_compromised_host_events"]
                ),
            },
        }
    )

    return specs


def run_paper_experiment(
    input_path: str | Path = INPUT_PATH,
    config_path: str | Path = CONFIG_PATH,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Run the canonical multi-level, multi-seed paper experiment."""

    config = load_config(config_path)
    belief_config = belief_config_from_dict(config)
    usefulness_config = usefulness_config_from_dict(config)

    mordor_df = load_mordor_processed_csv(Path(input_path))
    generated_df = mordor_to_generated_telemetry(mordor_df)

    records: list[dict[str, Any]] = []

    healthy_summary = _run_pipeline(
        generated_df,
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=0),
        belief_config,
        usefulness_config,
    )
    records.append(
        {
            "scenario": SCENARIO,
            "impairment_mode": ImpairmentMode.HEALTHY.value,
            "level_label": "baseline",
            "parameter_name": "none",
            "parameter_value": 0.0,
            "seed": 0,
            **healthy_summary,
        }
    )

    seeds = [int(seed) for seed in config["experiment"]["seeds"]]
    fixed_seed = int(config["experiment"]["fixed_seed"])
    for spec in _condition_specs(config):
        condition_seeds = seeds if spec["repeat_across_seeds"] else [fixed_seed]
        for seed in condition_seeds:
            impairment_config = ImpairmentConfig(
                mode=str(spec["impairment_mode"]),
                seed=seed,
                **spec["kwargs"],
            )
            summary = _run_pipeline(
                generated_df,
                impairment_config,
                belief_config,
                usefulness_config,
            )
            records.append(
                {
                    "scenario": SCENARIO,
                    "impairment_mode": spec["impairment_mode"],
                    "level_label": spec["level_label"],
                    "parameter_name": spec["parameter_name"],
                    "parameter_value": spec["parameter_value"],
                    "seed": seed,
                    **summary,
                }
            )
            # Repeated pandas pipelines allocate several intermediate frames.
            # Explicit collection keeps long multi-seed runs stable on modest
            # research workstations and CI containers.
            gc.collect()

    runs_df = pd.DataFrame.from_records(records)
    summary_df = summarize_runs(runs_df)
    aggregation_df = run_aggregation_sensitivity(
        generated_df,
        config,
        belief_config,
        usefulness_config,
    )
    return runs_df, summary_df, aggregation_df


def summarize_runs(runs_df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate run-level metrics to mean and sample standard deviation."""

    group_columns = [
        "scenario",
        "impairment_mode",
        "level_label",
        "parameter_name",
        "parameter_value",
    ]
    excluded_numeric = {"seed", "parameter_value"}
    numeric_columns = [
        column
        for column in runs_df.select_dtypes(include="number").columns
        if column not in excluded_numeric
    ]

    records: list[dict[str, Any]] = []
    for keys, group in runs_df.groupby(group_columns, sort=False, dropna=False):
        record = dict(zip(group_columns, keys))
        record["n_runs"] = int(len(group))
        for column in numeric_columns:
            record[f"{column}_mean"] = float(group[column].mean())
            std = group[column].std(ddof=1)
            record[f"{column}_std"] = 0.0 if pd.isna(std) else float(std)
        records.append(record)

    return pd.DataFrame.from_records(records)


def run_aggregation_sensitivity(
    generated_df: pd.DataFrame,
    config: dict[str, Any],
    belief_config: BeliefConfig,
    usefulness_config: UsefulnessConfig,
) -> pd.DataFrame:
    """Run deterministic healthy aggregation at the configured second windows."""

    records: list[dict[str, Any]] = []
    source_event_count = int(len(generated_df))

    variants: list[tuple[str, int | None, pd.DataFrame]] = [
        ("raw", None, generated_df)
    ]
    for window_seconds in config["aggregation"]["window_seconds"]:
        variants.append(
            (
                "aggregated",
                int(window_seconds),
                aggregate_generated_telemetry(generated_df, int(window_seconds)),
            )
        )

    for aggregation_mode, window_seconds, audit_df in variants:
        summary = _run_pipeline(
            audit_df,
            ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=0),
            belief_config,
            usefulness_config,
        )
        records.append(
            {
                "scenario": SCENARIO,
                "aggregation_mode": aggregation_mode,
                "aggregation_window_seconds": window_seconds,
                "audit_units": int(len(audit_df)),
                "source_events_represented": source_event_count,
                **summary,
            }
        )

    return pd.DataFrame.from_records(records)


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _git_working_tree_dirty() -> bool | None:
    """Return whether tracked/untracked files differ from HEAD, if Git exists."""

    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=PROJECT_ROOT,
            text=True,
        )
        return bool(status.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def write_manifest(
    config: dict[str, Any],
    input_path: str | Path,
    output_path: str | Path = MANIFEST_OUTPUT_PATH,
) -> Path:
    """Write exact experiment configuration and source identifiers."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "experiment": config["experiment"]["name"],
        "scenario": SCENARIO,
        "git_commit": _git_commit(),
        "git_working_tree_dirty": _git_working_tree_dirty(),
        "input_path": str(Path(input_path).relative_to(PROJECT_ROOT)),
        "input_sha256": _sha256(input_path),
        "config_path": str(CONFIG_PATH.relative_to(PROJECT_ROOT)),
        "config": config,
        "outputs": {
            "runs": str(RUNS_OUTPUT_PATH.relative_to(PROJECT_ROOT)),
            "summary": str(SUMMARY_OUTPUT_PATH.relative_to(PROJECT_ROOT)),
            "aggregation": str(AGGREGATION_OUTPUT_PATH.relative_to(PROJECT_ROOT)),
        },
    }
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output_path


def main() -> None:
    config = load_config(CONFIG_PATH)
    runs_df, summary_df, aggregation_df = run_paper_experiment(
        INPUT_PATH,
        CONFIG_PATH,
    )

    RUNS_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    runs_df.to_csv(RUNS_OUTPUT_PATH, index=False)
    summary_df.to_csv(SUMMARY_OUTPUT_PATH, index=False)
    aggregation_df.to_csv(AGGREGATION_OUTPUT_PATH, index=False)
    manifest_path = write_manifest(config, INPUT_PATH)

    print("Canonical Mordor paper experiment completed.")
    print(f"Runs: {RUNS_OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Summary: {SUMMARY_OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Aggregation: {AGGREGATION_OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Manifest: {manifest_path.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
