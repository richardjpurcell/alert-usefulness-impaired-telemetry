"""Defender-belief surface.

This module maintains a simple defender belief over host compromise state.

The first model is intentionally transparent rather than sophisticated:
- each host has a scalar belief: P(host is compromised);
- delivered telemetry events update that belief;
- missing telemetry does not directly update belief in this first version;
- belief quality is evaluated against the latent incident-state table.

This surface lets ASTRA compare telemetry delivery with telemetry usefulness:
delivered events matter only insofar as they improve the defender's maintained
estimate of incident state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from astra.incident_state import HostState
from astra.impairments import DELIVERED_COLUMNS
from astra.telemetry import TelemetryEventType


@dataclass(frozen=True)
class BeliefConfig:
    """Configuration for defender belief updating."""

    prior_compromise_probability: float = 0.05

    # Evidence weights by event type.
    auth_alert_weight: float = 0.08
    endpoint_alert_weight: float = 0.18
    network_alert_weight: float = 0.12

    # How strongly event_score affects update magnitude.
    score_weight: float = 0.25

    # Synthetic flood events should have little or negative value.
    synthetic_flood_penalty: float = 0.04

    # Small per-time-step relaxation toward the prior.
    # This prevents beliefs from becoming permanently fixed in short experiments.
    decay_to_prior: float = 0.01

    # Numerical clipping.
    min_probability: float = 0.001
    max_probability: float = 0.999


BELIEF_COLUMNS = [
    "time",
    "host_id",
    "belief_compromised",
    "belief_entropy",
    "true_state",
    "true_compromised",
    "belief_error",
]


EVENT_UPDATE_COLUMNS = [
    "event_id",
    "delivery_time",
    "generated_time",
    "host_id",
    "event_type",
    "event_score",
    "is_synthetic_flood",
    "belief_before",
    "belief_after",
    "belief_delta",
    "entropy_before",
    "entropy_after",
    "entropy_delta",
]


def validate_belief_config(config: BeliefConfig) -> None:
    """Validate belief-update configuration."""

    for name, value in [
        ("prior_compromise_probability", config.prior_compromise_probability),
        ("min_probability", config.min_probability),
        ("max_probability", config.max_probability),
        ("decay_to_prior", config.decay_to_prior),
    ]:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1.")

    if config.min_probability >= config.max_probability:
        raise ValueError("min_probability must be less than max_probability.")

    if not (
        config.min_probability
        <= config.prior_compromise_probability
        <= config.max_probability
    ):
        raise ValueError(
            "prior_compromise_probability must be between min_probability "
            "and max_probability."
        )

    for name, value in [
        ("auth_alert_weight", config.auth_alert_weight),
        ("endpoint_alert_weight", config.endpoint_alert_weight),
        ("network_alert_weight", config.network_alert_weight),
        ("score_weight", config.score_weight),
        ("synthetic_flood_penalty", config.synthetic_flood_penalty),
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


def binary_entropy(probability: float) -> float:
    """Return binary entropy in bits for a probability."""

    p = float(np.clip(probability, 1e-12, 1.0 - 1e-12))

    return float(-(p * np.log2(p) + (1.0 - p) * np.log2(1.0 - p)))


def _clip_probability(value: float, config: BeliefConfig) -> float:
    """Clip a belief probability to configured bounds."""

    return float(
        np.clip(
            value,
            config.min_probability,
            config.max_probability,
        )
    )


def _event_type_weight(event_type: str, config: BeliefConfig) -> float:
    """Return evidence weight for an event type."""

    if event_type == TelemetryEventType.AUTH_ALERT.value:
        return config.auth_alert_weight

    if event_type == TelemetryEventType.ENDPOINT_ALERT.value:
        return config.endpoint_alert_weight

    if event_type == TelemetryEventType.NETWORK_ALERT.value:
        return config.network_alert_weight

    # Unknown or flood event types are treated as low-value.
    return 0.0


def event_belief_delta(event: pd.Series, config: BeliefConfig) -> float:
    """Compute belief delta induced by one delivered event.

    Positive values increase P(compromised). Synthetic flood events apply a small
    penalty because they consume attention but do not provide incident evidence.
    """

    if bool(event.get("is_synthetic_flood", False)):
        return -config.synthetic_flood_penalty

    event_type = str(event["event_type"])
    event_score = float(event["event_score"])

    base_weight = _event_type_weight(event_type, config)
    score_component = config.score_weight * event_score

    return base_weight + score_component


def _state_at_time_lookup(state_df: pd.DataFrame) -> dict[tuple[int, str], str]:
    """Build lookup from (time, host_id) to true state."""

    return {
        (int(row["time"]), str(row["host_id"])): str(row["state"])
        for _, row in state_df.iterrows()
    }


def _true_state_for_time(
    state_lookup: dict[tuple[int, str], str],
    host_id: str,
    time: int,
) -> str:
    """Return true host state at a given time."""

    key = (time, host_id)

    if key not in state_lookup:
        raise KeyError(f"No true state for host_id={host_id}, time={time}")

    return state_lookup[key]


def _true_compromised(true_state: str) -> int:
    """Convert true state to binary compromised target."""

    return int(true_state == HostState.COMPROMISED.value)


def _all_times_and_hosts(state_df: pd.DataFrame) -> tuple[list[int], list[str]]:
    """Return sorted times and host IDs."""

    times = sorted(int(value) for value in state_df["time"].unique())
    host_ids = sorted(str(value) for value in state_df["host_id"].unique())

    return times, host_ids


def run_belief_update(
    state_df: pd.DataFrame,
    delivered_df: pd.DataFrame,
    config: BeliefConfig | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run defender belief updating from delivered telemetry.

    Parameters
    ----------
    state_df:
        Latent incident-state dataframe with columns: time, host_id, state.
    delivered_df:
        Delivered/impaired telemetry dataframe from ``apply_impairment``.
    config:
        Belief update configuration.

    Returns
    -------
    tuple[pandas.DataFrame, pandas.DataFrame]
        - belief_df: host-by-time belief state and quality columns.
        - event_updates_df: event-level belief deltas.
    """

    config = config or BeliefConfig()
    validate_belief_config(config)
    _validate_state_df(state_df)
    _validate_delivered_df(delivered_df)

    times, host_ids = _all_times_and_hosts(state_df)
    state_lookup = _state_at_time_lookup(state_df)

    beliefs: dict[str, float] = {
        host_id: config.prior_compromise_probability for host_id in host_ids
    }

    events_by_delivery_time: dict[int, pd.DataFrame] = {
        int(time): group.sort_values(["host_id", "event_id"]).reset_index(drop=True)
        for time, group in delivered_df.groupby("delivery_time")
    }

    belief_records: list[dict[str, Any]] = []
    event_update_records: list[dict[str, Any]] = []

    for time in times:
        # Decay beliefs slightly toward the prior before processing this time step.
        for host_id in host_ids:
            beliefs[host_id] = _clip_probability(
                beliefs[host_id]
                + config.decay_to_prior
                * (config.prior_compromise_probability - beliefs[host_id]),
                config,
            )

        if time in events_by_delivery_time:
            events = events_by_delivery_time[time]

            for _, event in events.iterrows():
                host_id = str(event["host_id"])

                if host_id not in beliefs:
                    # Ignore events for unknown hosts in this minimal version.
                    continue

                before = beliefs[host_id]
                entropy_before = binary_entropy(before)

                delta = event_belief_delta(event, config)
                after = _clip_probability(before + delta, config)
                entropy_after = binary_entropy(after)

                beliefs[host_id] = after

                event_update_records.append(
                    {
                        "event_id": str(event["event_id"]),
                        "delivery_time": int(event["delivery_time"]),
                        "generated_time": int(event["generated_time"]),
                        "host_id": host_id,
                        "event_type": str(event["event_type"]),
                        "event_score": float(event["event_score"]),
                        "is_synthetic_flood": bool(event["is_synthetic_flood"]),
                        "belief_before": before,
                        "belief_after": after,
                        "belief_delta": after - before,
                        "entropy_before": entropy_before,
                        "entropy_after": entropy_after,
                        "entropy_delta": entropy_after - entropy_before,
                    }
                )

        for host_id in host_ids:
            true_state = _true_state_for_time(state_lookup, host_id, time)
            true_compromised = _true_compromised(true_state)
            belief = beliefs[host_id]

            belief_records.append(
                {
                    "time": time,
                    "host_id": host_id,
                    "belief_compromised": belief,
                    "belief_entropy": binary_entropy(belief),
                    "true_state": true_state,
                    "true_compromised": true_compromised,
                    "belief_error": abs(belief - true_compromised),
                }
            )

    belief_df = pd.DataFrame.from_records(belief_records, columns=BELIEF_COLUMNS)
    event_updates_df = pd.DataFrame.from_records(
        event_update_records,
        columns=EVENT_UPDATE_COLUMNS,
    )

    return belief_df, event_updates_df


def summarize_belief(belief_df: pd.DataFrame) -> dict[str, float]:
    """Summarize defender belief quality."""

    missing = set(BELIEF_COLUMNS) - set(belief_df.columns)

    if missing:
        raise ValueError(f"belief_df is missing required columns: {sorted(missing)}")

    if belief_df.empty:
        return {
            "mean_belief_entropy": 0.0,
            "mean_belief_error": 0.0,
            "terminal_belief_entropy": 0.0,
            "terminal_belief_error": 0.0,
        }

    final_time = int(belief_df["time"].max())
    terminal = belief_df[belief_df["time"] == final_time]

    return {
        "mean_belief_entropy": float(belief_df["belief_entropy"].mean()),
        "mean_belief_error": float(belief_df["belief_error"].mean()),
        "terminal_belief_entropy": float(terminal["belief_entropy"].mean()),
        "terminal_belief_error": float(terminal["belief_error"].mean()),
    }


def summarize_event_updates(event_updates_df: pd.DataFrame) -> dict[str, int | float]:
    """Summarize event-level belief updates."""

    missing = set(EVENT_UPDATE_COLUMNS) - set(event_updates_df.columns)

    if missing:
        raise ValueError(
            f"event_updates_df is missing required columns: {sorted(missing)}"
        )

    if event_updates_df.empty:
        return {
            "updated_events": 0,
            "mean_belief_delta": 0.0,
            "mean_entropy_delta": 0.0,
            "entropy_reducing_events": 0,
            "entropy_increasing_events": 0,
        }

    entropy_delta = event_updates_df["entropy_delta"]

    return {
        "updated_events": int(len(event_updates_df)),
        "mean_belief_delta": float(event_updates_df["belief_delta"].mean()),
        "mean_entropy_delta": float(entropy_delta.mean()),
        "entropy_reducing_events": int((entropy_delta < 0).sum()),
        "entropy_increasing_events": int((entropy_delta > 0).sum()),
    }