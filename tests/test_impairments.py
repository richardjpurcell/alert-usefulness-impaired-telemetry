from astra.impairments import (
    ImpairmentConfig,
    ImpairmentMode,
    apply_impairment,
    summarize_impairment,
)
from astra.incident_state import IncidentStateConfig, generate_incident_state
from astra.telemetry import TelemetryConfig, generate_telemetry


def _sample_telemetry():
    state_df = generate_incident_state(
        IncidentStateConfig(
            num_hosts=10,
            num_initial_compromised=2,
            time_steps=5,
            seed=1,
        )
    )

    return generate_telemetry(
        state_df,
        TelemetryConfig(
            seed=1,
            benign_event_probability=1.0,
            suspicious_event_probability=1.0,
            compromised_event_probability=1.0,
        ),
    )


def test_healthy_impairment_delivers_all_events():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
    )

    assert len(delivered_df) == len(telemetry_df)
    assert delivered_df["is_delivered"].all()
    assert not delivered_df["is_synthetic_flood"].any()
    assert (delivered_df["generated_time"] == delivered_df["delivery_time"]).all()


def test_delay_impairment_delays_all_when_fraction_one():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.DELAY.value,
            seed=1,
            affected_event_fraction=1.0,
            delay_steps=3,
        ),
    )

    assert len(delivered_df) == len(telemetry_df)
    assert (
        delivered_df["delivery_time"] == delivered_df["generated_time"] + 3
    ).all()
    assert (delivered_df["impairment_status"] == "delayed").all()


def test_loss_impairment_drops_all_when_probability_one():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.LOSS.value,
            seed=1,
            drop_probability=1.0,
        ),
    )

    assert delivered_df.empty


def test_loss_impairment_keeps_all_when_probability_zero():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.LOSS.value,
            seed=1,
            drop_probability=0.0,
        ),
    )

    assert len(delivered_df) == len(telemetry_df)


def test_duplication_adds_duplicates_when_probability_one():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.DUPLICATION.value,
            seed=1,
            duplicate_probability=1.0,
        ),
    )

    assert len(delivered_df) == 2 * len(telemetry_df)
    assert delivered_df["parent_event_id"].notna().sum() == len(telemetry_df)


def test_alert_flood_adds_synthetic_background_events():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.ALERT_FLOOD.value,
            seed=1,
            flood_multiplier=2,
        ),
    )

    assert len(delivered_df) == 3 * len(telemetry_df)
    assert delivered_df["is_synthetic_flood"].sum() == 2 * len(telemetry_df)


def test_adversarial_suppression_removes_compromised_events_when_probability_one():
    telemetry_df = _sample_telemetry()

    compromised_event_count = int(
        (telemetry_df["source_state"] == "compromised").sum()
    )

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.ADVERSARIAL_SUPPRESSION.value,
            seed=1,
            suppress_compromised_host_events=True,
            suppression_probability=1.0,
        ),
    )

    assert len(delivered_df) == len(telemetry_df) - compromised_event_count
    assert not (delivered_df["source_state"] == "compromised").any()


def test_summarize_impairment_for_healthy_case():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(mode=ImpairmentMode.HEALTHY.value, seed=1),
    )

    summary = summarize_impairment(telemetry_df, delivered_df)

    assert summary["generated_events"] == len(telemetry_df)
    assert summary["delivered_events"] == len(telemetry_df)
    assert summary["missing_generated_events"] == 0
    assert summary["delivery_rate"] == 1.0
    assert summary["represented_delivery_rate"] == 1.0


def test_summarize_impairment_for_alert_flood_case():
    telemetry_df = _sample_telemetry()

    delivered_df = apply_impairment(
        telemetry_df,
        ImpairmentConfig(
            mode=ImpairmentMode.ALERT_FLOOD.value,
            seed=1,
            flood_multiplier=2,
        ),
    )

    summary = summarize_impairment(telemetry_df, delivered_df)

    assert summary["generated_events"] == len(telemetry_df)
    assert summary["delivered_events"] == 3 * len(telemetry_df)
    assert summary["synthetic_flood_events"] == 2 * len(telemetry_df)
    assert summary["missing_generated_events"] == 0
    assert summary["delivery_rate"] == 3.0
    assert summary["represented_delivery_rate"] == 1.0