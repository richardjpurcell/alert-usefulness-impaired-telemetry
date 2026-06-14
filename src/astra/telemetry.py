"""Telemetry surface.

This module generates synthetic security telemetry from a latent incident-state
table.

The generated events are intentionally simple. They are not meant to model a
real SOC pipeline in detail. They provide a controlled telemetry stream for
testing whether event delivery and event usefulness can separate under
impairment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import numpy as np
import pandas as pd

from astra.incident_state import HostState


class TelemetryEventType(StrEnum):
    """Synthetic telemetry event types."""

    AUTH_ALERT = "auth_alert"
    ENDPOINT_ALERT = "endpoint_alert"
    NETWORK_ALERT = "network_alert"


@dataclass(frozen=True)
class TelemetryConfig:
    """Configuration for synthetic telemetry generation."""

    seed: int = 42

    # Probability of generating events by source state.
    benign_event_probability: float = 0.02
    suspicious_event_probability: float = 0.20
    compromised_event_probability: float = 0.65

    # Event-type mix by source state.
    benign_event_weights: dict[str, float] | None = None
    suspicious_event_weights: dict[str, float] | None = None
    compromised_event_weights: dict[str, float] | None = None

    # Score ranges by source state. Scores are intentionally simple and
    # represent alert severity or detector confidence.
    benign_score_range: tuple[float, float] = (0.05, 0.35)
    suspicious_score_range: tuple[float, float] = (0.30, 0.70)
    compromised_score_range: tuple[float, float] = (0.60, 0.98)


DEFAULT_BENIGN_WEIGHTS = {
    TelemetryEventType.AUTH_ALERT.value: 0.50,
    TelemetryEventType.ENDPOINT_ALERT.value: 0.20,
    TelemetryEventType.NETWORK_ALERT.value: 0.30,
}

DEFAULT_SUSPICIOUS_WEIGHTS = {
    TelemetryEventType.AUTH_ALERT.value: 0.45,
    TelemetryEventType.ENDPOINT_ALERT.value: 0.30,
    TelemetryEventType.NETWORK_ALERT.value: 0.25,
}

DEFAULT_COMPROMISED_WEIGHTS = {
    TelemetryEventType.AUTH_ALERT.value: 0.20,
    TelemetryEventType.ENDPOINT_ALERT.value: 0.50,
    TelemetryEventType.NETWORK_ALERT.value: 0.30,
}


def _validate_probability(name: str, value: float) -> None:
    """Validate a probability value."""

    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1.")


def _validate_score_range(name: str, value: tuple[float, float]) -> None:
    """Validate an alert-score range."""

    low, high = value

    if not 0.0 <= low <= 1.0:
        raise ValueError(f"{name} lower bound must be between 0 and 1.")

    if not 0.0 <= high <= 1.0:
        raise ValueError(f"{name} upper bound must be between 0 and 1.")

    if low > high:
        raise ValueError(f"{name} lower bound cannot exceed upper bound.")


def _validate_weights(name: str, weights: dict[str, float]) -> None:
    """Validate event-type weights."""

    allowed = {event_type.value for event_type in TelemetryEventType}
    provided = set(weights)

    unknown = provided - allowed
    if unknown:
        raise ValueError(f"{name} contains unknown event types: {sorted(unknown)}")

    if not weights:
        raise ValueError(f"{name} cannot be empty.")

    for event_type, weight in weights.items():
        if weight < 0:
            raise ValueError(f"{name}[{event_type}] cannot be negative.")

    total = sum(weights.values())
    if total <= 0:
        raise ValueError(f"{name} must have positive total weight.")


def _normalize_weights(weights: dict[str, float]) -> dict[str, float]:
    """Normalize weights to probabilities."""

    total = sum(weights.values())
    return {key: value / total for key, value in weights.items()}


def _weights_for_state(config: TelemetryConfig, state: str) -> dict[str, float]:
    """Return normalized event-type weights for a given source state."""

    if state == HostState.BENIGN.value:
        weights = config.benign_event_weights or DEFAULT_BENIGN_WEIGHTS
    elif state == HostState.SUSPICIOUS.value:
        weights = config.suspicious_event_weights or DEFAULT_SUSPICIOUS_WEIGHTS
    elif state == HostState.COMPROMISED.value:
        weights = config.compromised_event_weights or DEFAULT_COMPROMISED_WEIGHTS
    else:
        raise ValueError(f"Unknown host state: {state}")

    _validate_weights(f"{state}_event_weights", weights)
    return _normalize_weights(weights)


def _event_probability_for_state(config: TelemetryConfig, state: str) -> float:
    """Return event-generation probability for a given source state."""

    if state == HostState.BENIGN.value:
        return config.benign_event_probability

    if state == HostState.SUSPICIOUS.value:
        return config.suspicious_event_probability

    if state == HostState.COMPROMISED.value:
        return config.compromised_event_probability

    raise ValueError(f"Unknown host state: {state}")


def _score_range_for_state(config: TelemetryConfig, state: str) -> tuple[float, float]:
    """Return alert-score range for a given source state."""

    if state == HostState.BENIGN.value:
        return config.benign_score_range

    if state == HostState.SUSPICIOUS.value:
        return config.suspicious_score_range

    if state == HostState.COMPROMISED.value:
        return config.compromised_score_range

    raise ValueError(f"Unknown host state: {state}")


def validate_telemetry_config(config: TelemetryConfig) -> None:
    """Validate synthetic telemetry configuration."""

    for name, value in [
        ("benign_event_probability", config.benign_event_probability),
        ("suspicious_event_probability", config.suspicious_event_probability),
        ("compromised_event_probability", config.compromised_event_probability),
    ]:
        _validate_probability(name, value)

    for name, value in [
        ("benign_score_range", config.benign_score_range),
        ("suspicious_score_range", config.suspicious_score_range),
        ("compromised_score_range", config.compromised_score_range),
    ]:
        _validate_score_range(name, value)

    if config.benign_event_weights is not None:
        _validate_weights("benign_event_weights", config.benign_event_weights)

    if config.suspicious_event_weights is not None:
        _validate_weights("suspicious_event_weights", config.suspicious_event_weights)

    if config.compromised_event_weights is not None:
        _validate_weights("compromised_event_weights", config.compromised_event_weights)


def _draw_event_type(
    rng: np.random.Generator,
    weights: dict[str, float],
) -> str:
    """Draw an event type from normalized weights."""

    event_types = list(weights.keys())
    probabilities = list(weights.values())

    return str(rng.choice(event_types, p=probabilities))


def _draw_event_score(
    rng: np.random.Generator,
    score_range: tuple[float, float],
) -> float:
    """Draw a synthetic alert score."""

    low, high = score_range
    return float(rng.uniform(low, high))


def _is_true_signal(state: str) -> bool:
    """Return whether an event is a true signal of abnormality."""

    return state in {
        HostState.SUSPICIOUS.value,
        HostState.COMPROMISED.value,
    }


def generate_telemetry(
    state_df: pd.DataFrame,
    config: TelemetryConfig | None = None,
) -> pd.DataFrame:
    """Generate synthetic telemetry events from a latent incident-state table.

    Parameters
    ----------
    state_df:
        DataFrame with columns: time, host_id, state.
    config:
        Telemetry generation configuration.

    Returns
    -------
    pandas.DataFrame
        Columns:
        - event_id: stable event identifier
        - time: time at which event is generated
        - host_id: host associated with event
        - event_type: synthetic telemetry type
        - event_score: severity/confidence-like score in [0, 1]
        - source_state: latent state that generated the event
        - is_true_signal: whether event corresponds to suspicious/compromised state
    """

    config = config or TelemetryConfig()
    validate_telemetry_config(config)

    required_columns = {"time", "host_id", "state"}
    missing = required_columns - set(state_df.columns)

    if missing:
        raise ValueError(f"state_df is missing required columns: {sorted(missing)}")

    rng = np.random.default_rng(config.seed)
    events: list[dict[str, Any]] = []

    sorted_state_df = state_df.sort_values(["time", "host_id"]).reset_index(drop=True)

    for _, row in sorted_state_df.iterrows():
        time = int(row["time"])
        host_id = str(row["host_id"])
        state = str(row["state"])

        event_probability = _event_probability_for_state(config, state)

        if rng.random() >= event_probability:
            continue

        weights = _weights_for_state(config, state)
        score_range = _score_range_for_state(config, state)

        event_type = _draw_event_type(rng, weights)
        event_score = _draw_event_score(rng, score_range)

        events.append(
            {
                "event_id": f"event_{len(events):06d}",
                "time": time,
                "host_id": host_id,
                "event_type": event_type,
                "event_score": event_score,
                "source_state": state,
                "is_true_signal": _is_true_signal(state),
            }
        )

    return pd.DataFrame.from_records(
        events,
        columns=[
            "event_id",
            "time",
            "host_id",
            "event_type",
            "event_score",
            "source_state",
            "is_true_signal",
        ],
    )


def summarize_telemetry(telemetry_df: pd.DataFrame) -> pd.DataFrame:
    """Summarize telemetry counts by time step and event type."""

    required_columns = {"time", "event_type"}
    missing = required_columns - set(telemetry_df.columns)

    if missing:
        raise ValueError(f"telemetry_df is missing required columns: {sorted(missing)}")

    if telemetry_df.empty:
        return pd.DataFrame(
            columns=[
                "time",
                TelemetryEventType.AUTH_ALERT.value,
                TelemetryEventType.ENDPOINT_ALERT.value,
                TelemetryEventType.NETWORK_ALERT.value,
                "total_events",
            ]
        )

    summary = (
        telemetry_df.groupby(["time", "event_type"])
        .size()
        .reset_index(name="count")
        .pivot(index="time", columns="event_type", values="count")
        .fillna(0)
        .astype(int)
        .reset_index()
    )

    for event_type in TelemetryEventType:
        if event_type.value not in summary.columns:
            summary[event_type.value] = 0

    summary["total_events"] = summary[
        [event_type.value for event_type in TelemetryEventType]
    ].sum(axis=1)

    return summary[
        [
            "time",
            TelemetryEventType.AUTH_ALERT.value,
            TelemetryEventType.ENDPOINT_ALERT.value,
            TelemetryEventType.NETWORK_ALERT.value,
            "total_events",
        ]
    ]


def telemetry_signal_summary(telemetry_df: pd.DataFrame) -> dict[str, int]:
    """Return true-signal and background/noise event counts."""

    required_columns = {"is_true_signal"}
    missing = required_columns - set(telemetry_df.columns)

    if missing:
        raise ValueError(f"telemetry_df is missing required columns: {sorted(missing)}")

    true_count = int(telemetry_df["is_true_signal"].sum())
    total_count = int(len(telemetry_df))

    return {
        "total_events": total_count,
        "true_signal_events": true_count,
        "background_events": total_count - true_count,
    }