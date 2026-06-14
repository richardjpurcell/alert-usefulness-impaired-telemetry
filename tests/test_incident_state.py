import pytest

from astra.incident_state import (
    HostState,
    IncidentStateConfig,
    compromised_hosts,
    generate_incident_state,
    state_counts_at_time,
    summarize_incident_state,
)


def test_generate_incident_state_shape():
    config = IncidentStateConfig(
        num_hosts=10,
        num_initial_compromised=2,
        time_steps=5,
        seed=1,
    )

    state_df = generate_incident_state(config)

    assert len(state_df) == 50
    assert set(state_df.columns) == {"time", "host_id", "state"}
    assert state_df["host_id"].nunique() == 10
    assert state_df["time"].nunique() == 5


def test_initial_compromised_count():
    config = IncidentStateConfig(
        num_hosts=10,
        num_initial_compromised=3,
        time_steps=5,
        seed=2,
    )

    state_df = generate_incident_state(config)
    counts = state_counts_at_time(state_df, time=0)

    assert counts[HostState.COMPROMISED.value] == 3


def test_summary_has_expected_columns():
    config = IncidentStateConfig(
        num_hosts=10,
        num_initial_compromised=2,
        time_steps=5,
        seed=3,
    )

    state_df = generate_incident_state(config)
    summary = summarize_incident_state(state_df)

    assert list(summary.columns) == [
        "time",
        HostState.BENIGN.value,
        HostState.SUSPICIOUS.value,
        HostState.COMPROMISED.value,
    ]

    assert len(summary) == 5


def test_compromised_hosts_returns_set():
    config = IncidentStateConfig(
        num_hosts=10,
        num_initial_compromised=2,
        time_steps=5,
        seed=4,
    )

    state_df = generate_incident_state(config)
    hosts = compromised_hosts(state_df, time=0)

    assert isinstance(hosts, set)
    assert len(hosts) == 2


def test_invalid_config_rejected():
    config = IncidentStateConfig(
        num_hosts=5,
        num_initial_compromised=10,
        time_steps=5,
    )

    with pytest.raises(ValueError):
        generate_incident_state(config)