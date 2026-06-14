"""Incident-state surface.

This module generates the latent security state of a small synthetic network.

The first model is intentionally simple:
- each host is benign, suspicious, or compromised;
- a small number of hosts begin compromised;
- compromised hosts may cause neighbouring hosts to become suspicious;
- suspicious hosts may become compromised over time.

This creates a hidden host-by-time incident state that later telemetry,
impairment, belief updating, and usefulness diagnostics can act upon.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

import numpy as np
import pandas as pd


class HostState(StrEnum):
    """Latent security state for a host."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"


@dataclass(frozen=True)
class IncidentStateConfig:
    """Configuration for synthetic incident-state generation."""

    num_hosts: int = 50
    num_initial_compromised: int = 5
    time_steps: int = 100
    suspicious_probability: float = 0.04
    compromise_probability: float = 0.15
    seed: int = 42


def _host_ids(num_hosts: int) -> list[str]:
    """Return stable host IDs."""

    return [f"host_{i:03d}" for i in range(num_hosts)]


def _validate_config(config: IncidentStateConfig) -> None:
    """Validate incident-state configuration."""

    if config.num_hosts <= 0:
        raise ValueError("num_hosts must be positive.")

    if config.time_steps <= 0:
        raise ValueError("time_steps must be positive.")

    if config.num_initial_compromised < 0:
        raise ValueError("num_initial_compromised cannot be negative.")

    if config.num_initial_compromised > config.num_hosts:
        raise ValueError("num_initial_compromised cannot exceed num_hosts.")

    for name, value in [
        ("suspicious_probability", config.suspicious_probability),
        ("compromise_probability", config.compromise_probability),
    ]:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1.")


def generate_incident_state(config: IncidentStateConfig) -> pd.DataFrame:
    """Generate a synthetic latent incident-state table.

    Returns
    -------
    pandas.DataFrame
        Columns:
        - time: integer time step
        - host_id: stable host identifier
        - state: one of benign, suspicious, compromised

    Notes
    -----
    This is not intended to be a realistic enterprise compromise model.
    It is a controlled latent process for testing whether telemetry delivery
    and telemetry usefulness can separate under impairment.
    """

    _validate_config(config)

    rng = np.random.default_rng(config.seed)
    hosts = _host_ids(config.num_hosts)

    states = np.full(
        shape=(config.time_steps, config.num_hosts),
        fill_value=HostState.BENIGN.value,
        dtype=object,
    )

    initial_compromised = rng.choice(
        config.num_hosts,
        size=config.num_initial_compromised,
        replace=False,
    )

    states[0, initial_compromised] = HostState.COMPROMISED.value

    for t in range(1, config.time_steps):
        states[t, :] = states[t - 1, :]

        compromised_previous = np.where(
            states[t - 1, :] == HostState.COMPROMISED.value
        )[0]

        benign_previous = np.where(
            states[t - 1, :] == HostState.BENIGN.value
        )[0]

        suspicious_previous = np.where(
            states[t - 1, :] == HostState.SUSPICIOUS.value
        )[0]

        # Benign hosts can become suspicious when compromise exists elsewhere.
        # This is a deliberately simple stand-in for lateral pressure,
        # suspicious auth behaviour, or anomalous activity near an incident.
        if len(compromised_previous) > 0 and len(benign_previous) > 0:
            suspicious_draws = rng.random(len(benign_previous))
            newly_suspicious = benign_previous[
                suspicious_draws < config.suspicious_probability
            ]
            states[t, newly_suspicious] = HostState.SUSPICIOUS.value

        # Suspicious hosts can become compromised.
        if len(suspicious_previous) > 0:
            compromise_draws = rng.random(len(suspicious_previous))
            newly_compromised = suspicious_previous[
                compromise_draws < config.compromise_probability
            ]
            states[t, newly_compromised] = HostState.COMPROMISED.value

    records = []
    for t in range(config.time_steps):
        for host_index, host_id in enumerate(hosts):
            records.append(
                {
                    "time": t,
                    "host_id": host_id,
                    "state": states[t, host_index],
                }
            )

    return pd.DataFrame.from_records(records)


def summarize_incident_state(state_df: pd.DataFrame) -> pd.DataFrame:
    """Summarize latent state counts by time step."""

    required_columns = {"time", "host_id", "state"}
    missing = required_columns - set(state_df.columns)

    if missing:
        raise ValueError(f"state_df is missing required columns: {sorted(missing)}")

    summary = (
        state_df.groupby(["time", "state"])
        .size()
        .reset_index(name="count")
        .pivot(index="time", columns="state", values="count")
        .fillna(0)
        .astype(int)
        .reset_index()
    )

    for state in HostState:
        if state.value not in summary.columns:
            summary[state.value] = 0

    return summary[
        [
            "time",
            HostState.BENIGN.value,
            HostState.SUSPICIOUS.value,
            HostState.COMPROMISED.value,
        ]
    ]


def state_counts_at_time(state_df: pd.DataFrame, time: int) -> dict[str, int]:
    """Return state counts for a single time step."""

    subset = state_df[state_df["time"] == time]

    counts = {state.value: 0 for state in HostState}
    counts.update(subset["state"].value_counts().to_dict())

    return counts


def compromised_hosts(state_df: pd.DataFrame, time: int | None = None) -> set[str]:
    """Return compromised host IDs.

    If time is provided, only that time step is used.
    Otherwise, any host compromised at any time is returned.
    """

    subset = state_df

    if time is not None:
        subset = subset[subset["time"] == time]

    return set(
        subset.loc[
            subset["state"] == HostState.COMPROMISED.value,
            "host_id",
        ].unique()
    )