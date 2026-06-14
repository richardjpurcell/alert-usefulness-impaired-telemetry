"""Telemetry impairment surface.

This module applies controlled impairments to generated security telemetry.

The goal is not to perfectly model every SOC or SIEM failure mode. The goal is
to create reproducible conditions in which delivered telemetry can be compared
with generated telemetry and later with useful telemetry.

Supported impairment modes:
- healthy: deliver events unchanged;
- delay: deliver a fraction of events late;
- loss: drop a fraction of events;
- duplication: duplicate a fraction of events;
- alert_flood: add low-value background events;
- adversarial_suppression: selectively suppress events from compromised hosts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import numpy as np
import pandas as pd

from astra.incident_state import HostState
from astra.telemetry import TelemetryEventType


class ImpairmentMode(StrEnum):
    """Supported telemetry impairment modes."""

    HEALTHY = "healthy"
    DELAY = "delay"
    LOSS = "loss"
    DUPLICATION = "duplication"
    ALERT_FLOOD = "alert_flood"
    ADVERSARIAL_SUPPRESSION = "adversarial_suppression"


@dataclass(frozen=True)
class ImpairmentConfig:
    """Configuration for telemetry impairment."""

    mode: str = ImpairmentMode.HEALTHY.value
    seed: int = 42

    # Delay
    delay_steps: int = 5
    affected_event_fraction: float = 0.30

    # Loss
    drop_probability: float = 0.30

    # Duplication
    duplicate_probability: float = 0.30

    # Alert flood
    flood_multiplier: int = 3
    flood_event_type: str = "low_value_network_alert"
    flood_score_range: tuple[float, float] = (0.05, 0.25)

    # Adversarial suppression
    suppress_compromised_host_events: bool = True
    suppression_probability: float = 0.50


REQUIRED_TELEMETRY_COLUMNS = {
    "event_id",
    "time",
    "host_id",
    "event_type",
    "event_score",
    "source_state",
    "is_true_signal",
}


DELIVERED_COLUMNS = [
    "event_id",
    "time",
    "host_id",
    "event_type",
    "event_score",
    "source_state",
    "is_true_signal",
    "generated_time",
    "delivery_time",
    "impairment_mode",
    "impairment_status",
    "is_delivered",
    "is_synthetic_flood",
    "parent_event_id",
]


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


def validate_impairment_config(config: ImpairmentConfig) -> None:
    """Validate impairment configuration."""

    allowed_modes = {mode.value for mode in ImpairmentMode}

    if config.mode not in allowed_modes:
        raise ValueError(
            f"Unknown impairment mode: {config.mode}. "
            f"Allowed modes: {sorted(allowed_modes)}"
        )

    if config.delay_steps < 0:
        raise ValueError("delay_steps cannot be negative.")

    if config.flood_multiplier < 0:
        raise ValueError("flood_multiplier cannot be negative.")

    for name, value in [
        ("affected_event_fraction", config.affected_event_fraction),
        ("drop_probability", config.drop_probability),
        ("duplicate_probability", config.duplicate_probability),
        ("suppression_probability", config.suppression_probability),
    ]:
        _validate_probability(name, value)

    _validate_score_range("flood_score_range", config.flood_score_range)


def _validate_telemetry_df(telemetry_df: pd.DataFrame) -> None:
    """Validate telemetry dataframe columns."""

    missing = REQUIRED_TELEMETRY_COLUMNS - set(telemetry_df.columns)

    if missing:
        raise ValueError(
            f"telemetry_df is missing required columns: {sorted(missing)}"
        )


def _base_delivered_frame(
    telemetry_df: pd.DataFrame,
    mode: str,
    status: str,
) -> pd.DataFrame:
    """Create a delivered telemetry frame with common impairment metadata."""

    delivered = telemetry_df.copy()

    delivered["generated_time"] = delivered["time"].astype(int)
    delivered["delivery_time"] = delivered["time"].astype(int)
    delivered["impairment_mode"] = mode
    delivered["impairment_status"] = status
    delivered["is_delivered"] = True
    delivered["is_synthetic_flood"] = False
    delivered["parent_event_id"] = pd.NA

    return delivered[DELIVERED_COLUMNS]


def apply_impairment(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig | None = None,
) -> pd.DataFrame:
    """Apply an impairment to generated telemetry.

    Parameters
    ----------
    telemetry_df:
        Generated telemetry dataframe from ``generate_telemetry``.
    config:
        Impairment configuration.

    Returns
    -------
    pandas.DataFrame
        Delivered/impaired telemetry dataframe with impairment metadata.

    Notes
    -----
    Dropped/suppressed events are not returned as delivered events. They will be
    counted later by comparing generated telemetry to delivered telemetry.
    """

    config = config or ImpairmentConfig()
    validate_impairment_config(config)
    _validate_telemetry_df(telemetry_df)

    if telemetry_df.empty:
        return pd.DataFrame(columns=DELIVERED_COLUMNS)

    if config.mode == ImpairmentMode.HEALTHY.value:
        return _apply_healthy(telemetry_df, config)

    if config.mode == ImpairmentMode.DELAY.value:
        return _apply_delay(telemetry_df, config)

    if config.mode == ImpairmentMode.LOSS.value:
        return _apply_loss(telemetry_df, config)

    if config.mode == ImpairmentMode.DUPLICATION.value:
        return _apply_duplication(telemetry_df, config)

    if config.mode == ImpairmentMode.ALERT_FLOOD.value:
        return _apply_alert_flood(telemetry_df, config)

    if config.mode == ImpairmentMode.ADVERSARIAL_SUPPRESSION.value:
        return _apply_adversarial_suppression(telemetry_df, config)

    raise ValueError(f"Unhandled impairment mode: {config.mode}")


def _apply_healthy(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Deliver events unchanged."""

    return _base_delivered_frame(
        telemetry_df,
        mode=config.mode,
        status="delivered",
    ).sort_values(["delivery_time", "host_id", "event_id"]).reset_index(drop=True)


def _apply_delay(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Delay a fraction of events."""

    rng = np.random.default_rng(config.seed)
    delivered = _base_delivered_frame(
        telemetry_df,
        mode=config.mode,
        status="delivered",
    )

    affected_mask = rng.random(len(delivered)) < config.affected_event_fraction

    delivered.loc[affected_mask, "delivery_time"] = (
        delivered.loc[affected_mask, "delivery_time"] + config.delay_steps
    )
    delivered.loc[affected_mask, "impairment_status"] = "delayed"

    return delivered.sort_values(
        ["delivery_time", "host_id", "event_id"]
    ).reset_index(drop=True)


def _apply_loss(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Drop a fraction of events."""

    rng = np.random.default_rng(config.seed)
    keep_mask = rng.random(len(telemetry_df)) >= config.drop_probability

    delivered = _base_delivered_frame(
        telemetry_df.loc[keep_mask].copy(),
        mode=config.mode,
        status="delivered",
    )

    delivered.loc[:, "impairment_status"] = "kept_after_loss"

    return delivered.sort_values(
        ["delivery_time", "host_id", "event_id"]
    ).reset_index(drop=True)


def _apply_duplication(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Duplicate a fraction of events."""

    rng = np.random.default_rng(config.seed)

    delivered = _base_delivered_frame(
        telemetry_df,
        mode=config.mode,
        status="delivered",
    )

    duplicate_mask = rng.random(len(delivered)) < config.duplicate_probability
    duplicate_source = delivered.loc[duplicate_mask].copy()

    if duplicate_source.empty:
        return delivered.sort_values(
            ["delivery_time", "host_id", "event_id"]
        ).reset_index(drop=True)

    duplicates = duplicate_source.copy()
    duplicates["parent_event_id"] = duplicates["event_id"]
    duplicates["event_id"] = [
        f"{event_id}_dup_{i:03d}"
        for i, event_id in enumerate(duplicate_source["event_id"])
    ]
    duplicates["impairment_status"] = "duplicated"

    combined = pd.concat([delivered, duplicates], ignore_index=True)

    return combined[DELIVERED_COLUMNS].sort_values(
        ["delivery_time", "host_id", "event_id"]
    ).reset_index(drop=True)


def _apply_alert_flood(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Add synthetic low-value background events."""

    rng = np.random.default_rng(config.seed)

    delivered = _base_delivered_frame(
        telemetry_df,
        mode=config.mode,
        status="delivered",
    )

    if config.flood_multiplier == 0 or telemetry_df.empty:
        return delivered.sort_values(
            ["delivery_time", "host_id", "event_id"]
        ).reset_index(drop=True)

    num_flood_events = len(telemetry_df) * config.flood_multiplier
    times = telemetry_df["time"].astype(int).to_numpy()
    host_ids = telemetry_df["host_id"].astype(str).unique()

    low, high = config.flood_score_range
    flood_events: list[dict[str, Any]] = []

    for i in range(num_flood_events):
        generated_time = int(rng.choice(times))
        host_id = str(rng.choice(host_ids))

        flood_events.append(
            {
                "event_id": f"flood_event_{i:06d}",
                "time": generated_time,
                "host_id": host_id,
                "event_type": config.flood_event_type,
                "event_score": float(rng.uniform(low, high)),
                "source_state": HostState.BENIGN.value,
                "is_true_signal": False,
                "generated_time": generated_time,
                "delivery_time": generated_time,
                "impairment_mode": config.mode,
                "impairment_status": "synthetic_flood",
                "is_delivered": True,
                "is_synthetic_flood": True,
                "parent_event_id": pd.NA,
            }
        )

    flood_df = pd.DataFrame.from_records(flood_events, columns=DELIVERED_COLUMNS)

    combined = pd.concat([delivered, flood_df], ignore_index=True)

    return combined[DELIVERED_COLUMNS].sort_values(
        ["delivery_time", "host_id", "event_id"]
    ).reset_index(drop=True)


def _apply_adversarial_suppression(
    telemetry_df: pd.DataFrame,
    config: ImpairmentConfig,
) -> pd.DataFrame:
    """Suppress a fraction of events from compromised hosts.

    This is a simple model of attacker-induced telemetry degradation. The
    attacker does not need to suppress all telemetry; selectively suppressing
    high-value telemetry from compromised hosts may be enough to degrade defender
    knowledge.
    """

    rng = np.random.default_rng(config.seed)

    if config.suppress_compromised_host_events:
        eligible_mask = (
            telemetry_df["source_state"] == HostState.COMPROMISED.value
        ).to_numpy()
    else:
        eligible_mask = np.ones(len(telemetry_df), dtype=bool)

    suppress_draws = rng.random(len(telemetry_df))
    suppress_mask = eligible_mask & (
        suppress_draws < config.suppression_probability
    )

    keep_mask = ~suppress_mask

    delivered = _base_delivered_frame(
        telemetry_df.loc[keep_mask].copy(),
        mode=config.mode,
        status="delivered",
    )

    delivered.loc[:, "impairment_status"] = "kept_after_suppression"

    return delivered.sort_values(
        ["delivery_time", "host_id", "event_id"]
    ).reset_index(drop=True)


def summarize_impairment(
    generated_df: pd.DataFrame,
    delivered_df: pd.DataFrame,
) -> dict[str, int | float]:
    """Summarize generated versus delivered telemetry.

    This summary is intentionally simple. More detailed usefulness metrics will
    be added later after belief updating exists.
    """

    _validate_telemetry_df(generated_df)

    missing = set(DELIVERED_COLUMNS) - set(delivered_df.columns)
    if missing:
        raise ValueError(
            f"delivered_df is missing required columns: {sorted(missing)}"
        )

    generated_count = int(len(generated_df))
    delivered_count = int(delivered_df["is_delivered"].sum())

    synthetic_flood_count = int(delivered_df["is_synthetic_flood"].sum())

    original_delivered_ids = set(
        delivered_df.loc[
            ~delivered_df["is_synthetic_flood"],
            "event_id",
        ].astype(str)
    )

    # Duplicated events have new event IDs. Their parent_event_id points back to
    # the generated event. Count unique generated events that were represented
    # in the delivered stream either directly or via duplicates.
    parent_ids = set(
        delivered_df.loc[
            delivered_df["parent_event_id"].notna(),
            "parent_event_id",
        ].astype(str)
    )

    represented_generated_ids = original_delivered_ids | parent_ids

    generated_ids = set(generated_df["event_id"].astype(str))
    missing_generated_count = len(generated_ids - represented_generated_ids)

    delayed_count = int(
        (delivered_df["delivery_time"] > delivered_df["generated_time"]).sum()
    )

    duplicate_count = int(delivered_df["parent_event_id"].notna().sum())

    delivery_rate = (
        delivered_count / generated_count if generated_count > 0 else 0.0
    )

    represented_delivery_rate = (
        len(generated_ids & represented_generated_ids) / generated_count
        if generated_count > 0
        else 0.0
    )

    return {
        "generated_events": generated_count,
        "delivered_events": delivered_count,
        "synthetic_flood_events": synthetic_flood_count,
        "duplicate_events": duplicate_count,
        "delayed_events": delayed_count,
        "missing_generated_events": int(missing_generated_count),
        "delivery_rate": float(delivery_rate),
        "represented_delivery_rate": float(represented_delivery_rate),
    }