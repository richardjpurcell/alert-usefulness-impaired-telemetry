"""Experiment orchestration.

Loads configs, runs synthetic experiments, and writes manifests/tables.

Current supported pipeline:

latent incident state
    -> generated telemetry
    -> impaired/delivered telemetry
    -> defender belief
    -> usefulness diagnostics
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from astra.belief import BeliefConfig, run_belief_update, summarize_belief, summarize_event_updates
from astra.impairments import ImpairmentConfig, apply_impairment, summarize_impairment
from astra.incident_state import IncidentStateConfig, generate_incident_state, summarize_incident_state
from astra.metrics import UsefulnessConfig, diagnose_event_usefulness, summarize_usefulness, usefulness_label_counts
from astra.telemetry import TelemetryConfig, generate_telemetry, summarize_telemetry, telemetry_signal_summary


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_config(config_path: str | Path) -> dict[str, Any]:
    """Load a YAML config file from the project root.

    Supports a simple `inherits` key that points to another YAML file in
    the same config directory or relative to the project root.
    """

    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    parent = config.get("inherits")
    if parent:
        parent_path = Path(parent)
        if not parent_path.is_absolute():
            candidate_same_dir = path.parent / parent_path
            candidate_project_root = PROJECT_ROOT / parent_path
            parent_path = candidate_same_dir if candidate_same_dir.exists() else candidate_project_root

        parent_config = load_config(parent_path)
        config = _deep_merge(parent_config, config)
        config.pop("inherits", None)

    return config


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge dictionaries."""

    merged = deepcopy(base)

    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def ensure_output_dirs() -> None:
    """Create output directories if they do not already exist."""

    for subdir in [
        "outputs/figures",
        "outputs/tables",
        "outputs/manifests",
        "outputs/logs",
    ]:
        (PROJECT_ROOT / subdir).mkdir(parents=True, exist_ok=True)


def _table_path(slug: str, suffix: str) -> Path:
    """Return a table output path."""

    return PROJECT_ROOT / "outputs" / "tables" / f"{slug}_{suffix}.csv"


def _manifest_path(slug: str) -> Path:
    """Return a manifest output path."""

    return PROJECT_ROOT / "outputs" / "manifests" / f"{slug}.json"


def _config_section(config: dict[str, Any], section: str) -> dict[str, Any]:
    """Return a config section, or an empty dict."""

    value = config.get(section, {})
    return value if isinstance(value, dict) else {}


def _build_incident_config(config: dict[str, Any]) -> IncidentStateConfig:
    """Build IncidentStateConfig from YAML config."""

    network = _config_section(config, "network")

    return IncidentStateConfig(
        num_hosts=int(network.get("num_hosts", 50)),
        num_initial_compromised=int(network.get("num_initial_compromised", 5)),
        time_steps=int(network.get("time_steps", 100)),
        seed=int(config.get("seed", 42)),
    )


def _build_telemetry_config(config: dict[str, Any]) -> TelemetryConfig:
    """Build TelemetryConfig from YAML config."""

    telemetry = _config_section(config, "telemetry")

    return TelemetryConfig(
        seed=int(config.get("seed", 42)),
        benign_event_probability=float(
            telemetry.get("benign_event_probability", 0.02)
        ),
        suspicious_event_probability=float(
            telemetry.get("suspicious_event_probability", 0.20)
        ),
        compromised_event_probability=float(
            telemetry.get("compromised_event_probability", 0.65)
        ),
    )


def _build_impairment_config(config: dict[str, Any]) -> ImpairmentConfig:
    """Build ImpairmentConfig from YAML config."""

    impairment = _config_section(config, "impairment")

    return ImpairmentConfig(
        mode=str(impairment.get("mode", "healthy")),
        seed=int(config.get("seed", 42)),
        delay_steps=int(impairment.get("delay_steps", 5)),
        affected_event_fraction=float(impairment.get("affected_event_fraction", 0.30)),
        drop_probability=float(impairment.get("drop_probability", 0.30)),
        false_positive_rate=float(impairment.get("false_positive_rate", 0.20)),
        false_negative_rate=float(impairment.get("false_negative_rate", 0.20)),
        duplicate_probability=float(impairment.get("duplicate_probability", 0.30)),
        flood_multiplier=int(impairment.get("flood_multiplier", 3)),
        flood_event_type=str(
            impairment.get("flood_event_type", "low_value_network_alert")
        ),
        suppress_compromised_host_events=bool(
            impairment.get("suppress_compromised_host_events", True)
        ),
        suppression_probability=float(impairment.get("suppression_probability", 0.50)),
    )


def _build_belief_config(config: dict[str, Any]) -> BeliefConfig:
    """Build BeliefConfig from YAML config."""

    belief = _config_section(config, "belief")

    return BeliefConfig(
        prior_compromise_probability=float(
            belief.get("prior_compromise_probability", 0.05)
        ),
        auth_alert_weight=float(belief.get("auth_alert_weight", 0.08)),
        endpoint_alert_weight=float(belief.get("endpoint_alert_weight", 0.18)),
        network_alert_weight=float(belief.get("network_alert_weight", 0.12)),
        score_weight=float(belief.get("score_weight", 0.25)),
        synthetic_flood_penalty=float(belief.get("synthetic_flood_penalty", 0.04)),
        decay_to_prior=float(belief.get("decay_to_prior", 0.01)),
    )


def _build_usefulness_config(config: dict[str, Any]) -> UsefulnessConfig:
    """Build UsefulnessConfig from YAML config."""

    usefulness = _config_section(config, "usefulness")

    return UsefulnessConfig(
        stale_after_steps=int(usefulness.get("stale_after_steps", 3)),
        min_abs_belief_delta=float(usefulness.get("min_abs_belief_delta", 0.01)),
        min_abs_entropy_delta=float(usefulness.get("min_abs_entropy_delta", 0.005)),
        min_error_improvement=float(usefulness.get("min_error_improvement", 0.01)),
        min_error_worsening=float(usefulness.get("min_error_worsening", 0.01)),
        label_stale_first=bool(usefulness.get("label_stale_first", True)),
        label_flood_first=bool(usefulness.get("label_flood_first", True)),
    )


def run_experiment(config: dict[str, Any]) -> dict[str, Any]:
    """Run one synthetic ASTRA experiment and write outputs."""

    ensure_output_dirs()

    slug = str(config.get("experiment_slug", "unnamed_experiment"))

    incident_config = _build_incident_config(config)
    telemetry_config = _build_telemetry_config(config)
    impairment_config = _build_impairment_config(config)
    belief_config = _build_belief_config(config)
    usefulness_config = _build_usefulness_config(config)

    state_df = generate_incident_state(incident_config)
    telemetry_df = generate_telemetry(state_df, telemetry_config)
    delivered_df = apply_impairment(telemetry_df, impairment_config)

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

    incident_summary_df = summarize_incident_state(state_df)
    telemetry_summary_df = summarize_telemetry(telemetry_df)
    label_counts_df = usefulness_label_counts(diagnostics_df)

    impairment_summary = summarize_impairment(telemetry_df, delivered_df)
    belief_summary = summarize_belief(belief_df)
    event_update_summary = summarize_event_updates(event_updates_df)
    signal_summary = telemetry_signal_summary(telemetry_df)
    usefulness_summary = summarize_usefulness(
        telemetry_df,
        delivered_df,
        diagnostics_df,
    )

    output_paths = {
        "incident_state": _table_path(slug, "incident_state"),
        "incident_summary": _table_path(slug, "incident_summary"),
        "generated_telemetry": _table_path(slug, "generated_telemetry"),
        "telemetry_summary": _table_path(slug, "telemetry_summary"),
        "delivered_telemetry": _table_path(slug, "delivered_telemetry"),
        "belief": _table_path(slug, "belief"),
        "event_updates": _table_path(slug, "event_updates"),
        "diagnostics": _table_path(slug, "diagnostics"),
        "usefulness_label_counts": _table_path(slug, "usefulness_label_counts"),
    }

    state_df.to_csv(output_paths["incident_state"], index=False)
    incident_summary_df.to_csv(output_paths["incident_summary"], index=False)
    telemetry_df.to_csv(output_paths["generated_telemetry"], index=False)
    telemetry_summary_df.to_csv(output_paths["telemetry_summary"], index=False)
    delivered_df.to_csv(output_paths["delivered_telemetry"], index=False)
    belief_df.to_csv(output_paths["belief"], index=False)
    event_updates_df.to_csv(output_paths["event_updates"], index=False)
    diagnostics_df.to_csv(output_paths["diagnostics"], index=False)
    label_counts_df.to_csv(output_paths["usefulness_label_counts"], index=False)

    manifest = {
        "experiment_slug": slug,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "pipeline": [
            "incident_state",
            "generated_telemetry",
            "impaired_telemetry",
            "defender_belief",
            "usefulness_diagnostics",
        ],
        "config": config,
        "summaries": {
            "signal": signal_summary,
            "impairment": impairment_summary,
            "belief": belief_summary,
            "event_updates": event_update_summary,
            "usefulness": usefulness_summary,
        },
        "outputs": {
            key: str(path.relative_to(PROJECT_ROOT))
            for key, path in output_paths.items()
        },
    }

    manifest_path = _manifest_path(slug)
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    manifest["outputs"]["manifest"] = str(manifest_path.relative_to(PROJECT_ROOT))

    return manifest


def main(config_path: str = "configs/synthetic_baseline.yaml") -> None:
    """Run a single configured experiment."""

    config = load_config(config_path)
    manifest = run_experiment(config)

    slug = manifest["experiment_slug"]

    print("ASTRA experiment completed.")
    print(f"Experiment slug: {slug}")
    print("Key summaries:")
    print(f"  generated events: {manifest['summaries']['impairment']['generated_events']}")
    print(f"  delivered events: {manifest['summaries']['impairment']['delivered_events']}")
    print(f"  useful fraction:  {manifest['summaries']['usefulness']['useful_event_fraction']:.3f}")
    print(f"  stale fraction:   {manifest['summaries']['usefulness']['stale_event_fraction']:.3f}")
    print(f"  misleading frac:  {manifest['summaries']['usefulness']['misleading_event_fraction']:.3f}")
    print(f"Manifest written to: outputs/manifests/{slug}.json")


def run_sweep(config_paths: list[str]) -> None:
    """Run multiple configured experiments."""

    print("ASTRA impairment sweep starting.")

    manifests = []

    for config_path in config_paths:
        print(f"\nRunning config: {config_path}")
        config = load_config(config_path)
        manifests.append(run_experiment(config))

        slug = manifests[-1]["experiment_slug"]
        usefulness = manifests[-1]["summaries"]["usefulness"]

        print(f"  completed: {slug}")
        print(f"  delivery rate:   {usefulness['delivery_rate']:.3f}")
        print(f"  useful fraction: {usefulness['useful_event_fraction']:.3f}")
        print(f"  stale fraction:  {usefulness['stale_event_fraction']:.3f}")

    sweep_summary = pd.DataFrame(
        [
            {
                "experiment_slug": manifest["experiment_slug"],
                **manifest["summaries"]["usefulness"],
                **{
                    f"belief_{key}": value
                    for key, value in manifest["summaries"]["belief"].items()
                },
            }
            for manifest in manifests
        ]
    )

    ensure_output_dirs()
    sweep_path = PROJECT_ROOT / "outputs" / "tables" / "impairment_sweep_summary.csv"
    sweep_summary.to_csv(sweep_path, index=False)

    print("\nASTRA impairment sweep completed.")
    print(f"Sweep summary written to: {sweep_path.relative_to(PROJECT_ROOT)}")