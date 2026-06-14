"""Usefulness-diagnostics surface.

This module classifies delivered telemetry events according to simple,
auditable usefulness diagnostics.

The first version intentionally uses operational definitions that can be
computed from existing ASTRA surfaces:
- generated telemetry;
- delivered/impaired telemetry;
- event-level belief updates;
- latent incident state.

The purpose is not to define usefulness universally. The purpose is to support
controlled experiments where delivered telemetry can be separated from telemetry
that improves defender knowledge.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import pandas as pd

from astra.belief import EVENT_UPDATE_COLUMNS, binary_entropy
from astra.impairments import DELIVERED_COLUMNS, summarize_impairment
from astra.incident_state import HostState


class UsefulnessLabel(StrEnum):
    """Event-level usefulness labels."""

    USEFUL = "useful"
    STALE = "stale"
    REDUNDANT = "redundant"
    MISLEADING = "misleading"
    UNINFORMATIVE = "uninformative"
    FLOOD = "flood"


@dataclass(frozen=True)
class UsefulnessConfig:
    """Configuration for usefulness diagnostics."""

    stale_after_steps: int = 3
    min_abs_belief_delta: float = 0.01
    min_abs_entropy_delta: float = 0.005

    # Useful if error improves by at least this much.
    min_error_improvement: float = 0.01

    # Misleading if error worsens by at least this much.
    min_error_worsening: float = 0.01

    # If true, staleness dominates other labels.
    label_stale_first: bool = True

    # If true, synthetic flood events get their own label.
    label_flood_first: bool = True


EVENT_DIAGNOSTIC_COLUMNS = [
    "event_id",
    "host_id",
    "generated_time",
    "delivery_time",
    "latency",
    "event_type",
    "event_score",
    "is_synthetic_flood",
    "true_state_at_generated_time",
    "true_state_at_delivery_time",
    "true_compromised_at_delivery_time",
    "belief_before",
    "belief_after",
    "belief_delta",
    "entropy_before",
    "entropy_after",
    "entropy_delta",
    "belief_error_before",
    "belief_error_after",
    "belief_error_delta",
    "usefulness_label",
]


SUMMARY_COLUMNS = [
    "generated_events",
    "delivered_events",
    "synthetic_flood_events",
    "duplicate_events",
    "delayed_events",
    "missing_generated_events",
    "delivery_rate",
    "represented_delivery_rate",
    "updated_events",
    "useful_events",
    "stale_events",
    "redundant_events",
    "misleading_events",
    "uninformative_events",
    "flood_events",
    "useful_event_fraction",
    "stale_event_fraction",
    "redundant_event_fraction",
    "misleading_event_fraction",
    "mean_latency",
    "mean_belief_delta",
    "mean_entropy_delta",
    "mean_belief_error_delta",
]


def validate_usefulness_config(config: UsefulnessConfig) -> None:
    """Validate usefulness diagnostic configuration."""

    if config.stale_after_steps < 0:
        raise ValueError("stale_after_steps cannot be negative.")

    for name, value in [
        ("min_abs_belief_delta", config.min_abs_belief_delta),
        ("min_abs_entropy_delta", config.min_abs_entropy_delta),
        ("min_error_improvement", config.min_error_improvement),
        ("min_error_worsening", config.min_error_worsening),
    ]:
        if value < 0:
            raise ValueError(f"{name} cannot be negative.")


def _validate_state_df(state_df: pd.DataFrame) -> None:
    """Validate latent incident-state dataframe."""

    required_columns = {"time", "host_id", "state"}
    missing = required_columns - set(state_df.columns)

    if missing:
        raise ValueError(f"state_df is missing required columns: {sorted(missing)}")


def _validate_delivered_df(delivered_df: pd.DataFrame) -> None:
    """Validate delivered telemetry dataframe."""

    missing = set(DELIVERED_COLUMNS) - set(delivered_df.columns)

    if missing:
        raise ValueError(f"delivered_df is missing required columns: {sorted(missing)}")


def _validate_event_updates_df(event_updates_df: pd.DataFrame) -> None:
    """Validate event-level belief update dataframe."""

    missing = set(EVENT_UPDATE_COLUMNS) - set(event_updates_df.columns)

    if missing:
        raise ValueError(
            f"event_updates_df is missing required columns: {sorted(missing)}"
        )


def _state_lookup(state_df: pd.DataFrame) -> dict[tuple[int, str], str]:
    """Build lookup from (time, host_id) to true latent state."""

    return {
        (int(row["time"]), str(row["host_id"])): str(row["state"])
        for _, row in state_df.iterrows()
    }


def _true_state(
    lookup: dict[tuple[int, str], str],
    time: int,
    host_id: str,
) -> str:
    """Return true state for host/time.

    If an event is delivered beyond the simulated state horizon, use the final
    available time for that host. This allows delayed events to be diagnosed
    even when their delivery time exceeds the original simulation window.
    """

    key = (time, host_id)
    if key in lookup:
        return lookup[key]

    host_times = [t for (t, h) in lookup if h == host_id]

    if not host_times:
        raise KeyError(f"No states found for host_id={host_id}")

    clipped_time = max(t for t in host_times if t <= max(host_times))
    return lookup[(clipped_time, host_id)]


def _true_compromised(state: str) -> int:
    """Convert latent state into binary compromised target."""

    return int(state == HostState.COMPROMISED.value)


def _belief_error(belief: float, true_compromised: int) -> float:
    """Absolute error between compromise belief and true binary state."""

    return abs(float(belief) - int(true_compromised))


def classify_event_usefulness(
    row: pd.Series,
    config: UsefulnessConfig | None = None,
) -> str:
    """Classify one delivered event into a usefulness label."""

    config = config or UsefulnessConfig()
    validate_usefulness_config(config)

    if config.label_flood_first and bool(row["is_synthetic_flood"]):
        return UsefulnessLabel.FLOOD.value

    if config.label_stale_first and int(row["latency"]) > config.stale_after_steps:
        return UsefulnessLabel.STALE.value

    if float(row["belief_error_delta"]) >= config.min_error_worsening:
        return UsefulnessLabel.MISLEADING.value

    if float(row["belief_error_delta"]) <= -config.min_error_improvement:
        return UsefulnessLabel.USEFUL.value

    small_belief_change = abs(float(row["belief_delta"])) < config.min_abs_belief_delta
    small_entropy_change = abs(float(row["entropy_delta"])) < config.min_abs_entropy_delta

    if small_belief_change and small_entropy_change:
        return UsefulnessLabel.REDUNDANT.value

    if float(row["entropy_delta"]) <= -config.min_abs_entropy_delta:
        return UsefulnessLabel.USEFUL.value

    return UsefulnessLabel.UNINFORMATIVE.value


def diagnose_event_usefulness(
    state_df: pd.DataFrame,
    delivered_df: pd.DataFrame,
    event_updates_df: pd.DataFrame,
    config: UsefulnessConfig | None = None,
) -> pd.DataFrame:
    """Create event-level usefulness diagnostics.

    Parameters
    ----------
    state_df:
        Latent incident-state dataframe.
    delivered_df:
        Delivered/impaired telemetry dataframe.
    event_updates_df:
        Event-level belief update dataframe from ``run_belief_update``.
    config:
        Usefulness diagnostic configuration.

    Returns
    -------
    pandas.DataFrame
        Event-level diagnostics with usefulness labels.
    """

    config = config or UsefulnessConfig()
    validate_usefulness_config(config)
    _validate_state_df(state_df)
    _validate_delivered_df(delivered_df)
    _validate_event_updates_df(event_updates_df)

    if event_updates_df.empty:
        return pd.DataFrame(columns=EVENT_DIAGNOSTIC_COLUMNS)

    lookup = _state_lookup(state_df)

    delivered_subset = delivered_df[
        [
            "event_id",
            "source_state",
            "impairment_status",
            "parent_event_id",
        ]
    ].copy()

    merged = event_updates_df.merge(
        delivered_subset,
        on="event_id",
        how="left",
        validate="one_to_one",
    )

    records: list[dict[str, Any]] = []

    for _, row in merged.iterrows():
        host_id = str(row["host_id"])
        generated_time = int(row["generated_time"])
        delivery_time = int(row["delivery_time"])
        latency = delivery_time - generated_time

        true_state_generated = _true_state(lookup, generated_time, host_id)
        true_state_delivery = _true_state(lookup, delivery_time, host_id)
        true_compromised_delivery = _true_compromised(true_state_delivery)

        belief_before = float(row["belief_before"])
        belief_after = float(row["belief_after"])

        belief_error_before = _belief_error(
            belief_before,
            true_compromised_delivery,
        )
        belief_error_after = _belief_error(
            belief_after,
            true_compromised_delivery,
        )

        belief_error_delta = belief_error_after - belief_error_before

        record = {
            "event_id": str(row["event_id"]),
            "host_id": host_id,
            "generated_time": generated_time,
            "delivery_time": delivery_time,
            "latency": latency,
            "event_type": str(row["event_type"]),
            "event_score": float(row["event_score"]),
            "is_synthetic_flood": bool(row["is_synthetic_flood"]),
            "true_state_at_generated_time": true_state_generated,
            "true_state_at_delivery_time": true_state_delivery,
            "true_compromised_at_delivery_time": true_compromised_delivery,
            "belief_before": belief_before,
            "belief_after": belief_after,
            "belief_delta": float(row["belief_delta"]),
            "entropy_before": float(row["entropy_before"]),
            "entropy_after": float(row["entropy_after"]),
            "entropy_delta": float(row["entropy_delta"]),
            "belief_error_before": belief_error_before,
            "belief_error_after": belief_error_after,
            "belief_error_delta": belief_error_delta,
        }

        record["usefulness_label"] = classify_event_usefulness(
            pd.Series(record),
            config,
        )

        records.append(record)

    return pd.DataFrame.from_records(records, columns=EVENT_DIAGNOSTIC_COLUMNS)


def summarize_usefulness(
    generated_df: pd.DataFrame,
    delivered_df: pd.DataFrame,
    diagnostics_df: pd.DataFrame,
) -> dict[str, int | float]:
    """Summarize delivery and usefulness diagnostics together."""

    base = summarize_impairment(generated_df, delivered_df)

    missing = set(EVENT_DIAGNOSTIC_COLUMNS) - set(diagnostics_df.columns)
    if missing:
        raise ValueError(
            f"diagnostics_df is missing required columns: {sorted(missing)}"
        )

    updated_events = int(len(diagnostics_df))

    label_counts = {
        label.value: int((diagnostics_df["usefulness_label"] == label.value).sum())
        for label in UsefulnessLabel
    }

    useful_events = label_counts[UsefulnessLabel.USEFUL.value]
    stale_events = label_counts[UsefulnessLabel.STALE.value]
    redundant_events = label_counts[UsefulnessLabel.REDUNDANT.value]
    misleading_events = label_counts[UsefulnessLabel.MISLEADING.value]
    uninformative_events = label_counts[UsefulnessLabel.UNINFORMATIVE.value]
    flood_events = label_counts[UsefulnessLabel.FLOOD.value]

    delivered_events = int(base["delivered_events"])

    def fraction(count: int) -> float:
        return float(count / delivered_events) if delivered_events > 0 else 0.0

    if diagnostics_df.empty:
        mean_latency = 0.0
        mean_belief_delta = 0.0
        mean_entropy_delta = 0.0
        mean_belief_error_delta = 0.0
    else:
        mean_latency = float(diagnostics_df["latency"].mean())
        mean_belief_delta = float(diagnostics_df["belief_delta"].mean())
        mean_entropy_delta = float(diagnostics_df["entropy_delta"].mean())
        mean_belief_error_delta = float(
            diagnostics_df["belief_error_delta"].mean()
        )

    summary = {
        **base,
        "updated_events": updated_events,
        "useful_events": useful_events,
        "stale_events": stale_events,
        "redundant_events": redundant_events,
        "misleading_events": misleading_events,
        "uninformative_events": uninformative_events,
        "flood_events": flood_events,
        "useful_event_fraction": fraction(useful_events),
        "stale_event_fraction": fraction(stale_events),
        "redundant_event_fraction": fraction(redundant_events),
        "misleading_event_fraction": fraction(misleading_events),
        "mean_latency": mean_latency,
        "mean_belief_delta": mean_belief_delta,
        "mean_entropy_delta": mean_entropy_delta,
        "mean_belief_error_delta": mean_belief_error_delta,
    }

    return {key: summary[key] for key in SUMMARY_COLUMNS}


def usefulness_label_counts(diagnostics_df: pd.DataFrame) -> pd.DataFrame:
    """Return usefulness label counts as a dataframe."""

    missing = {"usefulness_label"} - set(diagnostics_df.columns)
    if missing:
        raise ValueError(
            f"diagnostics_df is missing required columns: {sorted(missing)}"
        )

    if diagnostics_df.empty:
        return pd.DataFrame(columns=["usefulness_label", "count"])

    return (
        diagnostics_df["usefulness_label"]
        .value_counts()
        .rename_axis("usefulness_label")
        .reset_index(name="count")
        .sort_values("usefulness_label")
        .reset_index(drop=True)
    )