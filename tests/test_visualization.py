import pandas as pd
import pytest

from astra.visualization import (
    make_label_count_figure,
    make_sweep_figures,
    plot_belief_quality,
    plot_delivery_vs_usefulness,
    plot_usefulness_label_counts,
)


def _sample_sweep_summary():
    return pd.DataFrame(
        [
            {
                "experiment_slug": "exp01_synthetic_baseline",
                "delivery_rate": 1.0,
                "useful_event_fraction": 0.9,
                "belief_mean_belief_entropy": 0.4,
                "belief_mean_belief_error": 0.1,
            },
            {
                "experiment_slug": "exp02_delay_impairment",
                "delivery_rate": 1.0,
                "useful_event_fraction": 0.5,
                "belief_mean_belief_entropy": 0.6,
                "belief_mean_belief_error": 0.2,
            },
            {
                "experiment_slug": "exp06_alert_flood",
                "delivery_rate": 6.0,
                "useful_event_fraction": 0.161,
                "belief_mean_belief_entropy": 0.464,
                "belief_mean_belief_error": 0.164,
            },
        ]
    )


def _sample_label_counts():
    return pd.DataFrame(
        [
            {"usefulness_label": "useful", "count": 10},
            {"usefulness_label": "stale", "count": 3},
            {"usefulness_label": "misleading", "count": 1},
        ]
    )


def test_plot_delivery_vs_usefulness_writes_file(tmp_path):
    output_path = tmp_path / "delivery_vs_usefulness.png"

    written = plot_delivery_vs_usefulness(
        _sample_sweep_summary(),
        output_path,
    )

    assert written == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_plot_belief_quality_writes_file(tmp_path):
    output_path = tmp_path / "belief_quality.png"

    written = plot_belief_quality(
        _sample_sweep_summary(),
        output_path,
    )

    assert written == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_plot_usefulness_label_counts_writes_file(tmp_path):
    output_path = tmp_path / "label_counts.png"

    written = plot_usefulness_label_counts(
        _sample_label_counts(),
        output_path,
    )

    assert written == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_make_sweep_figures_writes_standard_figures(tmp_path):
    sweep_path = tmp_path / "impairment_sweep_summary.csv"
    output_dir = tmp_path / "figures"

    _sample_sweep_summary().to_csv(sweep_path, index=False)

    outputs = make_sweep_figures(
        sweep_summary_path=sweep_path,
        output_dir=output_dir,
    )

    assert set(outputs) == {"delivery_vs_usefulness", "belief_quality"}

    for path in outputs.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_make_label_count_figure_writes_file(tmp_path):
    label_counts_path = tmp_path / "label_counts.csv"
    output_path = tmp_path / "label_counts.png"

    _sample_label_counts().to_csv(label_counts_path, index=False)

    written = make_label_count_figure(
        label_counts_path=label_counts_path,
        output_path=output_path,
        title="Test usefulness labels",
    )

    assert written == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0

def test_plot_delivery_vs_usefulness_rejects_missing_columns(tmp_path):
    df = _sample_sweep_summary().drop(columns=["useful_event_fraction"])

    with pytest.raises(ValueError, match="missing required columns"):
        plot_delivery_vs_usefulness(
            df,
            tmp_path / "delivery_vs_usefulness.png",
        )


def test_plot_belief_quality_rejects_missing_columns(tmp_path):
    df = _sample_sweep_summary().drop(columns=["belief_mean_belief_error"])

    with pytest.raises(ValueError, match="missing required columns"):
        plot_belief_quality(
            df,
            tmp_path / "belief_quality.png",
        )