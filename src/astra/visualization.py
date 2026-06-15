"""Visualization utilities.

Creates first-pass figures for ASTRA experiments.

The visualizations are intentionally simple and paper-oriented:
- delivery rate versus useful-event fraction;
- usefulness label composition/counts;
- belief quality summaries.

These figures support the core ASTRA claim:

Security telemetry that arrives is not always useful.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_FIGSIZE = (8, 4.8)
DEFAULT_DPI = 160

DEFAULT_EXPERIMENT_LABELS = {
    "exp01_synthetic_baseline": "Baseline",
    "exp02_delay_impairment": "Delay",
    "exp03_loss_impairment": "Loss",
    "exp04_noise_impairment": "Noise",
    "exp05_adversarial_suppression": "Suppression",
    "exp06_alert_flood": "Alert flood",
}


def _ensure_parent(path: str | Path) -> Path:
    """Ensure the parent directory for a path exists."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def _require_columns(df: pd.DataFrame, required: set[str], name: str) -> None:
    """Validate dataframe columns."""

    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"{name} is missing required columns: {sorted(missing)}")

def _experiment_labels(
    experiment_slugs: pd.Series,
    label_map: dict[str, str] | None = None,
) -> pd.Series:
    """Map experiment slugs to readable labels."""

    labels = label_map or DEFAULT_EXPERIMENT_LABELS

    return experiment_slugs.astype(str).map(lambda slug: labels.get(slug, slug))


def plot_delivery_vs_usefulness(
    sweep_summary_df: pd.DataFrame,
    output_path: str | Path,
    label_map: dict[str, str] | None = None,
    title: str = "Telemetry delivery versus usefulness",
) -> Path:
    """Plot delivery rate and useful-event fraction by experiment.

    This figure highlights the core ASTRA claim: telemetry volume or delivery
    rate can separate from the fraction of delivered events that are useful for
    defender belief maintenance.
    """

    _require_columns(
        sweep_summary_df,
        {"experiment_slug", "delivery_rate", "useful_event_fraction"},
        "sweep_summary_df",
    )

    output_path = _ensure_parent(output_path)

    plot_df = sweep_summary_df.copy()
    plot_df["Experiment"] = _experiment_labels(
        plot_df["experiment_slug"],
        label_map=label_map,
    )

    x = range(len(plot_df))
    width = 0.38

    fig, ax = plt.subplots(figsize=DEFAULT_FIGSIZE)

    ax.bar(
        [i - width / 2 for i in x],
        plot_df["delivery_rate"],
        width=width,
        label="Delivery rate",
    )
    ax.bar(
        [i + width / 2 for i in x],
        plot_df["useful_event_fraction"],
        width=width,
        label="Useful-event fraction",
    )

    ax.axhline(
        y=1.0,
        linestyle="--",
        linewidth=1,
        alpha=0.6,
    )

    ax.set_title(title)
    ax.set_ylabel("Rate / fraction")
    ax.set_xlabel("Experiment")
    ax.set_xticks(list(x))
    ax.set_xticklabels(plot_df["Experiment"], rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def plot_usefulness_label_counts(
    label_counts_df: pd.DataFrame,
    output_path: str | Path,
    title: str = "Usefulness-state composition",
) -> Path:
    """Plot usefulness label counts for one experiment.

    Parameters
    ----------
    label_counts_df:
        DataFrame with columns usefulness_label and count.
    output_path:
        Destination PNG path.
    title:
        Figure title.

    Returns
    -------
    pathlib.Path
        Written figure path.
    """

    _require_columns(
        label_counts_df,
        {"usefulness_label", "count"},
        "label_counts_df",
    )

    output_path = _ensure_parent(output_path)

    plot_df = label_counts_df.copy()
    plot_df["usefulness_label"] = plot_df["usefulness_label"].astype(str)

    fig, ax = plt.subplots(figsize=DEFAULT_FIGSIZE)

    x = range(len(plot_df))
    ax.bar(x, plot_df["count"])
    ax.set_title(title)
    ax.set_ylabel("Event count")
    ax.set_xlabel("Usefulness label")
    ax.set_xticks(range(len(plot_df)))
    ax.set_xticklabels(plot_df["usefulness_label"], rotation=30, ha="right")
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def plot_belief_quality(
    sweep_summary_df: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot belief entropy and belief error by experiment.

    The sweep summary stores belief metrics with a `belief_` prefix.
    """

    _require_columns(
        sweep_summary_df,
        {
            "experiment_slug",
            "belief_mean_belief_entropy",
            "belief_mean_belief_error",
        },
        "sweep_summary_df",
    )

    output_path = _ensure_parent(output_path)

    plot_df = sweep_summary_df.copy()
    plot_df["Experiment"] = _experiment_labels(plot_df["experiment_slug"])

    x = range(len(plot_df))
    width = 0.38

    fig, ax = plt.subplots(figsize=DEFAULT_FIGSIZE)

    ax.bar(
        [i - width / 2 for i in x],
        plot_df["belief_mean_belief_entropy"],
        width=width,
        label="Mean belief entropy",
    )
    ax.bar(
        [i + width / 2 for i in x],
        plot_df["belief_mean_belief_error"],
        width=width,
        label="Mean belief error",
    )

    ax.set_title("Belief quality under telemetry impairment")
    ax.set_ylabel("Mean value")
    ax.set_xlabel("Experiment")
    ax.set_xticks(list(x))
    ax.set_xticklabels(plot_df["Experiment"], rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def make_sweep_figures(
    sweep_summary_path: str | Path = "outputs/tables/impairment_sweep_summary.csv",
    output_dir: str | Path = "outputs/figures",
) -> dict[str, Path]:
    """Create standard figures from an impairment sweep summary.

    Parameters
    ----------
    sweep_summary_path:
        CSV path produced by `run_sweep`.
    output_dir:
        Directory where figure PNG files should be written.

    Returns
    -------
    dict[str, pathlib.Path]
        Figure names mapped to output paths.
    """

    sweep_summary_path = Path(sweep_summary_path)
    output_dir = Path(output_dir)

    if not sweep_summary_path.exists():
        raise FileNotFoundError(f"Sweep summary not found: {sweep_summary_path}")

    sweep_summary_df = pd.read_csv(sweep_summary_path)

    outputs = {
        "delivery_vs_usefulness": plot_delivery_vs_usefulness(
            sweep_summary_df,
            output_dir / "delivery_vs_usefulness.png",
        ),
        "belief_quality": plot_belief_quality(
            sweep_summary_df,
            output_dir / "belief_quality.png",
        ),
    }

    return outputs


def make_label_count_figure(
    label_counts_path: str | Path,
    output_path: str | Path,
    title: str = "Usefulness-state composition",
) -> Path:
    """Create a usefulness label count figure from a label-count CSV."""

    label_counts_path = Path(label_counts_path)

    if not label_counts_path.exists():
        raise FileNotFoundError(f"Label counts file not found: {label_counts_path}")

    label_counts_df = pd.read_csv(label_counts_path)

    return plot_usefulness_label_counts(
        label_counts_df,
        output_path,
        title=title,
    )