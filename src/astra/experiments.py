"""Experiment orchestration.

Loads configs, runs synthetic or dataset-backed experiments, writes manifests,
tables, and figures.

This first version is intentionally minimal: it verifies that the project
structure, config loading, output directories, and experiment entry points work.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_config(config_path: str | Path) -> dict[str, Any]:
    """Load a YAML config file from the project root."""

    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def ensure_output_dirs() -> None:
    """Create output directories if they do not already exist."""

    for subdir in [
        "outputs/figures",
        "outputs/tables",
        "outputs/manifests",
        "outputs/logs",
    ]:
        (PROJECT_ROOT / subdir).mkdir(parents=True, exist_ok=True)


def write_manifest(config: dict[str, Any]) -> Path:
    """Write a simple experiment manifest."""

    ensure_output_dirs()

    slug = config.get("experiment_slug", "unnamed_experiment")
    manifest_path = PROJECT_ROOT / "outputs" / "manifests" / f"{slug}.json"

    manifest = {
        "experiment_slug": slug,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "placeholder_run_completed",
        "note": (
            "This is a scaffold run. Synthetic incident-state generation, "
            "telemetry impairment, belief update, and usefulness metrics "
            "will be implemented next."
        ),
        "config": config,
    }

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest_path


def main(config_path: str = "configs/synthetic_baseline.yaml") -> None:
    """Run a single configured experiment."""

    config = load_config(config_path)
    manifest_path = write_manifest(config)

    print("ASTRA experiment scaffold run completed.")
    print(f"Experiment slug: {config.get('experiment_slug')}")
    print(f"Manifest written to: {manifest_path}")


def run_sweep(config_paths: list[str]) -> None:
    """Run multiple configured experiments."""

    print("ASTRA impairment sweep scaffold starting.")

    for config_path in config_paths:
        print(f"\nRunning config: {config_path}")
        main(config_path=config_path)

    print("\nASTRA impairment sweep scaffold completed.")