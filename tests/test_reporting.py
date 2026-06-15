import pandas as pd
import pytest


from astra.reporting import (
    DEFAULT_EXPERIMENT_LABELS,
    INTERPRETATION_SUMMARY_COLUMNS,
    PAPER_SUMMARY_COLUMNS,
    make_interpretation_summary_table,
    make_markdown_interpretation_table,
    make_markdown_summary_table,
    make_paper_summary_table,
    write_markdown_interpretation_table,
    write_markdown_summary_table,
    write_paper_summary_table,
)


def _sample_sweep_summary():
    return pd.DataFrame(
        [
            {
                "experiment_slug": "exp01_synthetic_baseline",
                "delivery_rate": 1.0,
                "useful_event_fraction": 0.96721,
                "stale_event_fraction": 0.0,
                "misleading_event_fraction": 0.03279,
                "belief_mean_belief_entropy": 0.18888,
                "belief_mean_belief_error": 0.06111,
            },
            {
                "experiment_slug": "exp02_delay_impairment",
                "delivery_rate": 1.0,
                "useful_event_fraction": 0.54849,
                "stale_event_fraction": 0.28142,
                "misleading_event_fraction": 0.014,
                "belief_mean_belief_entropy": 0.20333,
                "belief_mean_belief_error": 0.06555,
            },
            {
                "experiment_slug": "unknown_experiment",
                "delivery_rate": 0.5,
                "useful_event_fraction": 0.25,
                "stale_event_fraction": 0.125,
                "misleading_event_fraction": 0.0625,
                "belief_mean_belief_entropy": 0.3333,
                "belief_mean_belief_error": 0.2222,
            },
        ]
    )


def test_make_paper_summary_table_has_expected_columns():
    table = make_paper_summary_table(_sample_sweep_summary())

    assert list(table.columns) == PAPER_SUMMARY_COLUMNS


def test_make_paper_summary_table_maps_known_experiment_labels():
    table = make_paper_summary_table(_sample_sweep_summary())

    assert table.loc[0, "Experiment"] == DEFAULT_EXPERIMENT_LABELS[
        "exp01_synthetic_baseline"
    ]
    assert table.loc[1, "Experiment"] == DEFAULT_EXPERIMENT_LABELS[
        "exp02_delay_impairment"
    ]


def test_make_paper_summary_table_keeps_unknown_experiment_slug():
    table = make_paper_summary_table(_sample_sweep_summary())

    assert table.loc[2, "Experiment"] == "unknown_experiment"


def test_make_paper_summary_table_rounds_values():
    table = make_paper_summary_table(_sample_sweep_summary(), digits=2)

    assert table.loc[0, "Useful-event fraction"] == 0.97
    assert table.loc[0, "Misleading-event fraction"] == 0.03
    assert table.loc[1, "Stale-event fraction"] == 0.28


def test_make_paper_summary_table_accepts_custom_label_map():
    table = make_paper_summary_table(
        _sample_sweep_summary(),
        label_map={
            "exp01_synthetic_baseline": "Healthy",
            "exp02_delay_impairment": "Delayed",
        },
    )

    assert table.loc[0, "Experiment"] == "Healthy"
    assert table.loc[1, "Experiment"] == "Delayed"


def test_make_paper_summary_table_rejects_missing_columns():
    df = _sample_sweep_summary().drop(columns=["delivery_rate"])

    with pytest.raises(ValueError, match="missing required columns"):
        make_paper_summary_table(df)


def test_make_paper_summary_table_rejects_negative_digits():
    with pytest.raises(ValueError, match="digits cannot be negative"):
        make_paper_summary_table(_sample_sweep_summary(), digits=-1)


def test_write_paper_summary_table_writes_csv(tmp_path):
    sweep_path = tmp_path / "impairment_sweep_summary.csv"
    output_path = tmp_path / "paper_summary_table.csv"

    _sample_sweep_summary().to_csv(sweep_path, index=False)

    written = write_paper_summary_table(
        sweep_summary_path=sweep_path,
        output_path=output_path,
    )

    assert written == output_path
    assert output_path.exists()

    loaded = pd.read_csv(output_path)

    assert list(loaded.columns) == PAPER_SUMMARY_COLUMNS
    assert loaded.loc[0, "Experiment"] == "Baseline"


def test_make_markdown_summary_table_returns_markdown():
    markdown = make_markdown_summary_table(_sample_sweep_summary())

    assert "| Experiment" in markdown
    assert "Baseline" in markdown
    assert "Delay" in markdown


def test_write_markdown_summary_table_writes_file(tmp_path):
    sweep_path = tmp_path / "impairment_sweep_summary.csv"
    output_path = tmp_path / "paper_summary_table.md"

    _sample_sweep_summary().to_csv(sweep_path, index=False)

    written = write_markdown_summary_table(
        sweep_summary_path=sweep_path,
        output_path=output_path,
    )

    assert written == output_path
    assert output_path.exists()

    text = output_path.read_text(encoding="utf-8")

    assert "| Experiment" in text
    assert "Baseline" in text


def test_make_markdown_summary_table_uses_fixed_decimal_places():
    sweep_summary_df = pd.DataFrame(
        {
            "experiment_slug": [
                "exp01_synthetic_baseline",
                "exp05_adversarial_suppression",
                "exp06_alert_flood",
            ],
            "delivery_rate": [1.0, 0.5, 6.0],
            "useful_event_fraction": [0.967, 0.935, 0.161],
            "stale_event_fraction": [0.0, 0.0, 0.0],
            "misleading_event_fraction": [0.033, 0.065, 0.006],
            "belief_mean_belief_entropy": [0.189, 0.261, 0.464],
            "belief_mean_belief_error": [0.062, 0.085, 0.164],
        }
    )

    markdown = make_markdown_summary_table(sweep_summary_df)

    assert "| Baseline | 1.000 | 0.967 | 0.000 | 0.033 | 0.189 | 0.062 |" in markdown
    assert "| Suppression | 0.500 | 0.935 | 0.000 | 0.065 | 0.261 | 0.085 |" in markdown
    assert "| Alert flood | 6.000 | 0.161 | 0.000 | 0.006 | 0.464 | 0.164 |" in markdown

def test_make_interpretation_summary_table_has_expected_columns():
    table = make_interpretation_summary_table(_sample_sweep_summary())

    assert list(table.columns) == INTERPRETATION_SUMMARY_COLUMNS


def test_make_interpretation_summary_table_maps_known_experiment_labels():
    table = make_interpretation_summary_table(_sample_sweep_summary())

    assert table.loc[0, "Experiment"] == "Baseline"
    assert table.loc[1, "Experiment"] == "Delay"


def test_make_interpretation_summary_table_keeps_unknown_experiment_slug():
    table = make_interpretation_summary_table(_sample_sweep_summary())

    assert table.loc[2, "Experiment"] == "unknown_experiment"


def test_make_interpretation_summary_table_adds_known_interpretations():
    table = make_interpretation_summary_table(_sample_sweep_summary())

    assert table.loc[0, "Delivery-side observation"] == "Delivery remains complete."
    assert table.loc[0, "Usefulness-side observation"] == (
        "Most delivered events are useful."
    )
    assert table.loc[0, "Interpretation"] == "Healthy telemetry-to-belief coupling."

    assert table.loc[1, "Usefulness-side observation"] == (
        "Stale-event fraction increases."
    )


def test_make_interpretation_summary_table_handles_unknown_interpretations():
    table = make_interpretation_summary_table(_sample_sweep_summary())

    assert table.loc[2, "Delivery-side observation"] == "Not specified."
    assert table.loc[2, "Usefulness-side observation"] == "Not specified."
    assert table.loc[2, "Interpretation"] == "No interpretation has been defined."


def test_make_markdown_interpretation_table_returns_markdown():
    markdown = make_markdown_interpretation_table(_sample_sweep_summary())

    assert "| Experiment" in markdown
    assert "| Delivery-side observation" in markdown
    assert "Healthy telemetry-to-belief coupling." in markdown
    assert "Events can arrive but no longer support timely belief maintenance." in markdown


def test_write_markdown_interpretation_table_writes_file(tmp_path):
    sweep_path = tmp_path / "impairment_sweep_summary.csv"
    output_path = tmp_path / "interpretation_summary_table.md"

    _sample_sweep_summary().to_csv(sweep_path, index=False)

    written = write_markdown_interpretation_table(
        sweep_summary_path=sweep_path,
        output_path=output_path,
    )

    assert written == output_path
    assert output_path.exists()

    text = output_path.read_text(encoding="utf-8")

    assert "| Experiment" in text
    assert "Baseline" in text
    assert "Healthy telemetry-to-belief coupling." in text