
"""Create Mordor-specific paper figures for ASTRA.

The figures are generated from paper-facing summary tables in:

    outputs/tables/

and written to:

    outputs/figures/

These figures support the narrowed ASTRA paper claim:

Security telemetry that arrives is not always useful.

The figures are intentionally simple and paper-oriented:
- delivery rate versus represented delivery rate under Mordor impairments;
- raw versus aggregated usefulness-state fractions;
- optional belief-weight sensitivity for saturation robustness.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_FIGSIZE = (8, 4.8)
DEFAULT_DPI = 160

TABLE_DIR = Path("outputs/tables")
FIGURE_DIR = Path("outputs/figures")

MORDOR_MODE_LABELS = {
    "healthy": "Healthy",
    "delay": "Delay",
    "loss": "Loss",
    "noise": "Noise",
    "duplication": "Duplication",
    "alert_flood": "Alert flood",
    "adversarial_suppression": "Suppression",
}

MODE_ORDER = [
    "healthy",
    "delay",
    "loss",
    "noise",
    "duplication",
    "alert_flood",
    "adversarial_suppression",
]


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


def _ordered_modes(df: pd.DataFrame) -> pd.DataFrame:
    """Order Mordor impairment modes for consistent paper figures."""

    plot_df = df.copy()
    plot_df["mode_order"] = plot_df["impairment_mode"].map(
        {mode: idx for idx, mode in enumerate(MODE_ORDER)}
    )
    plot_df = plot_df.sort_values("mode_order").drop(columns=["mode_order"])
    plot_df["Mode"] = plot_df["impairment_mode"].map(
        lambda mode: MORDOR_MODE_LABELS.get(str(mode), str(mode))
    )
    return plot_df


def plot_mordor_delivery_vs_represented(
    summary_df: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot delivery rate versus represented delivery rate under impairment.

    This figure supports the result that delivered volume and represented
    original evidence can separate under noise, duplication, flood, and loss.
    """

    _require_columns(
        summary_df,
        {"impairment_mode", "delivery_rate", "represented_delivery_rate"},
        "summary_df",
    )

    output_path = _ensure_parent(output_path)
    plot_df = _ordered_modes(summary_df)

    x = list(range(len(plot_df)))
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
        plot_df["represented_delivery_rate"],
        width=width,
        label="Represented delivery rate",
    )

    ax.axhline(y=1.0, linestyle="--", linewidth=1, alpha=0.6)

    ax.set_title("Mordor delivery versus represented evidence")
    ax.set_ylabel("Rate")
    ax.set_xlabel("Impairment mode")
    ax.set_xticks(x)
    ax.set_xticklabels(plot_df["Mode"], rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def plot_mordor_raw_vs_aggregated_usefulness(
    aggregation_df: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot raw versus aggregated usefulness-state fractions.

    Counts are normalized within each audit unit because raw replay has 6,026
    units while aggregation has 44 units. This makes the figure about
    usefulness profile rather than raw volume.
    """

    _require_columns(
        aggregation_df,
        {
            "aggregation_mode",
            "aggregation_window_steps",
            "delivered_events",
            "useful_events",
            "redundant_events",
            "misleading_events",
            "saturated_update_fraction",
        },
        "aggregation_df",
    )

    output_path = _ensure_parent(output_path)

    plot_df = aggregation_df.copy()
    plot_df = plot_df[
        (plot_df["impairment_mode"] == "healthy")
        & (
            (plot_df["aggregation_mode"] == "raw")
            | (
                (plot_df["aggregation_mode"] == "aggregated")
                & (plot_df["aggregation_window_steps"] == 5)
            )
        )
    ].copy()

    if len(plot_df) != 2:
        raise ValueError(
            "Expected exactly one raw row and one aggregated window=5 row "
            f"for healthy mode; found {len(plot_df)} rows."
        )

    def label_row(row: pd.Series) -> str:
        if row["aggregation_mode"] == "raw":
            return "Raw"
        return "Aggregated"

    plot_df["Audit unit"] = plot_df.apply(label_row, axis=1)

    for column in ["useful_events", "redundant_events", "misleading_events"]:
        plot_df[f"{column}_fraction"] = plot_df[column] / plot_df["delivered_events"]

    x = list(range(len(plot_df)))
    width = 0.18

    series = [
        ("useful_events_fraction", "Useful"),
        ("redundant_events_fraction", "Redundant"),
        ("misleading_events_fraction", "Misleading"),
        ("saturated_update_fraction", "Saturated"),
    ]

    fig, ax = plt.subplots(figsize=DEFAULT_FIGSIZE)

    offsets = [-1.5 * width, -0.5 * width, 0.5 * width, 1.5 * width]
    for offset, (column, label) in zip(offsets, series):
        ax.bar(
            [i + offset for i in x],
            plot_df[column],
            width=width,
            label=label,
        )

    ax.set_title("Mordor raw versus aggregated usefulness profile")
    ax.set_ylabel("Fraction of audit units")
    ax.set_xlabel("Audit unit")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(x)
    ax.set_xticklabels(plot_df["Audit unit"])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def plot_mordor_weight_sensitivity(
    weight_df: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot saturation fraction across belief-weight configurations.

    This is optional for the paper. It supports the claim that lower weights
    delay but do not remove the repeated-event saturation pattern.
    """

    _require_columns(
        weight_df,
        {"belief_config", "saturated_update_fraction", "redundant_event_fraction"},
        "weight_df",
    )

    output_path = _ensure_parent(output_path)

    label_map = {
        "default": "Default",
        "half_weights": "Half",
        "quarter_weights": "Quarter",
        "low_weights": "Low",
    }
    order = ["default", "half_weights", "quarter_weights", "low_weights"]

    plot_df = weight_df.copy()
    plot_df["order"] = plot_df["belief_config"].map(
        {config: idx for idx, config in enumerate(order)}
    )
    plot_df = plot_df.sort_values("order")
    plot_df["Config"] = plot_df["belief_config"].map(
        lambda config: label_map.get(str(config), str(config))
    )

    x = list(range(len(plot_df)))
    width = 0.38

    fig, ax = plt.subplots(figsize=DEFAULT_FIGSIZE)

    ax.bar(
        [i - width / 2 for i in x],
        plot_df["saturated_update_fraction"],
        width=width,
        label="Saturated-update fraction",
    )
    ax.bar(
        [i + width / 2 for i in x],
        plot_df["redundant_event_fraction"],
        width=width,
        label="Redundant-update fraction",
    )

    ax.set_title("Mordor belief-weight sensitivity")
    ax.set_ylabel("Fraction")
    ax.set_xlabel("Belief-weight configuration")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(x)
    ax.set_xticklabels(plot_df["Config"])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DEFAULT_DPI)
    plt.close(fig)

    return output_path


def make_mordor_paper_figures(
    table_dir: str | Path = TABLE_DIR,
    output_dir: str | Path = FIGURE_DIR,
) -> dict[str, Path]:
    """Create all Mordor-specific paper figures."""

    table_dir = Path(table_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    belief_summary_path = table_dir / "mordor_belief_usefulness_summary.csv"
    aggregation_path = table_dir / "mordor_event_aggregation_sensitivity.csv"
    weight_path = table_dir / "mordor_belief_weight_sensitivity.csv"

    for path in [belief_summary_path, aggregation_path, weight_path]:
        if not path.exists():
            raise FileNotFoundError(f"Required table not found: {path}")

    belief_summary_df = pd.read_csv(belief_summary_path)
    aggregation_df = pd.read_csv(aggregation_path)
    weight_df = pd.read_csv(weight_path)

    outputs = {
        "mordor_delivery_vs_represented": plot_mordor_delivery_vs_represented(
            belief_summary_df,
            output_dir / "mordor_delivery_vs_represented.png",
        ),
        "mordor_raw_vs_aggregated_usefulness": (
            plot_mordor_raw_vs_aggregated_usefulness(
                aggregation_df,
                output_dir / "mordor_raw_vs_aggregated_usefulness.png",
            )
        ),
        "mordor_weight_sensitivity": plot_mordor_weight_sensitivity(
            weight_df,
            output_dir / "mordor_weight_sensitivity.png",
        ),
    }

    return outputs


if __name__ == "__main__":
    written = make_mordor_paper_figures()
    for name, path in written.items():
        print(f"{name}: {path}")

