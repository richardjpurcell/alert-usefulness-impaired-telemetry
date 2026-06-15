"""Reporting utilities.

Creates paper-facing summary tables from ASTRA experiment outputs.

The goal is to convert raw experiment summaries into compact, readable tables
for notes, README sections, and paper drafts.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


DEFAULT_EXPERIMENT_LABELS = {
    "exp01_synthetic_baseline": "Baseline",
    "exp02_delay_impairment": "Delay",
    "exp03_loss_impairment": "Loss",
    "exp04_noise_impairment": "Noise",
    "exp05_adversarial_suppression": "Suppression",
    "exp06_alert_flood": "Alert flood",
}


PAPER_SUMMARY_COLUMNS = [
    "Experiment",
    "Delivery rate",
    "Useful-event fraction",
    "Stale-event fraction",
    "Misleading-event fraction",
    "Mean belief entropy",
    "Mean belief error",
]

INTERPRETATION_SUMMARY_COLUMNS = [
    "Experiment",
    "Delivery-side observation",
    "Usefulness-side observation",
    "Interpretation",
]


DEFAULT_EXPERIMENT_INTERPRETATIONS = {
    "exp01_synthetic_baseline": {
        "Delivery-side observation": "Delivery remains complete.",
        "Usefulness-side observation": "Most delivered events are useful.",
        "Interpretation": "Healthy telemetry-to-belief coupling.",
    },
    "exp02_delay_impairment": {
        "Delivery-side observation": "Delivery remains complete.",
        "Usefulness-side observation": "Stale-event fraction increases.",
        "Interpretation": (
            "Events can arrive but no longer support timely belief maintenance."
        ),
    },
    "exp03_loss_impairment": {
        "Delivery-side observation": "Delivery decreases.",
        "Usefulness-side observation": (
            "Useful fraction remains high among delivered events."
        ),
        "Interpretation": (
            "Lower volume is not automatically lower usefulness density."
        ),
    },
    "exp04_noise_impairment": {
        "Delivery-side observation": "Delivery remains high.",
        "Usefulness-side observation": "Misleading events and belief error increase.",
        "Interpretation": (
            "Corrupted telemetry can weaken defender belief despite delivery."
        ),
    },
    "exp05_adversarial_suppression": {
        "Delivery-side observation": "Delivery decreases.",
        "Usefulness-side observation": "Belief entropy increases.",
        "Interpretation": "Missing high-value evidence degrades defender certainty.",
    },
    "exp06_alert_flood": {
        "Delivery-side observation": "Delivery volume inflates.",
        "Usefulness-side observation": "Useful-event fraction collapses.",
        "Interpretation": "More telemetry can produce less useful evidence per event.",
    },
}


REQUIRED_SWEEP_COLUMNS = {
    "experiment_slug",
    "delivery_rate",
    "useful_event_fraction",
    "stale_event_fraction",
    "misleading_event_fraction",
    "belief_mean_belief_entropy",
    "belief_mean_belief_error",
}


def _require_columns(df: pd.DataFrame, required: set[str], name: str) -> None:
    """Validate dataframe columns."""

    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"{name} is missing required columns: {sorted(missing)}")


def _round_series(series: pd.Series, digits: int) -> pd.Series:
    """Round a numeric series to a fixed number of digits."""

    return pd.to_numeric(series, errors="raise").round(digits)


def _format_markdown_value(value: object, digits: int) -> str:
    """Format a table value for paper-facing Markdown output."""

    if isinstance(value, float):
        return f"{value:.{digits}f}"

    return str(value)

def _dataframe_to_markdown(
    table: pd.DataFrame,
    digits: int = 3,
) -> str:
    """Render a DataFrame as a simple GitHub-style Markdown table."""

    header = "| " + " | ".join(table.columns) + " |"
    separator = "| " + " | ".join(["---"] * len(table.columns)) + " |"

    rows = []
    for _, row in table.iterrows():
        formatted_values = [
            _format_markdown_value(value, digits)
            for value in row.values
        ]
        rows.append("| " + " | ".join(formatted_values) + " |")

    return "\n".join([header, separator, *rows])

def make_paper_summary_table(
    sweep_summary_df: pd.DataFrame,
    label_map: dict[str, str] | None = None,
    digits: int = 3,
) -> pd.DataFrame:
    """Create a compact paper-facing summary table.

    Parameters
    ----------
    sweep_summary_df:
        DataFrame produced by ``run_sweep``.
    label_map:
        Optional map from experiment slug to short display label.
    digits:
        Number of decimal places for numeric values.

    Returns
    -------
    pandas.DataFrame
        Compact table with readable column names and rounded values.
    """

    _require_columns(
        sweep_summary_df,
        REQUIRED_SWEEP_COLUMNS,
        "sweep_summary_df",
    )

    if digits < 0:
        raise ValueError("digits cannot be negative.")

    label_map = label_map or DEFAULT_EXPERIMENT_LABELS

    table = pd.DataFrame(
        {
            "Experiment": sweep_summary_df["experiment_slug"]
            .astype(str)
            .map(lambda slug: label_map.get(slug, slug)),
            "Delivery rate": _round_series(sweep_summary_df["delivery_rate"], digits),
            "Useful-event fraction": _round_series(
                sweep_summary_df["useful_event_fraction"],
                digits,
            ),
            "Stale-event fraction": _round_series(
                sweep_summary_df["stale_event_fraction"],
                digits,
            ),
            "Misleading-event fraction": _round_series(
                sweep_summary_df["misleading_event_fraction"],
                digits,
            ),
            "Mean belief entropy": _round_series(
                sweep_summary_df["belief_mean_belief_entropy"],
                digits,
            ),
            "Mean belief error": _round_series(
                sweep_summary_df["belief_mean_belief_error"],
                digits,
            ),
        }
    )

    return table[PAPER_SUMMARY_COLUMNS]


def write_paper_summary_table(
    sweep_summary_path: str | Path = "outputs/tables/impairment_sweep_summary.csv",
    output_path: str | Path = "outputs/tables/paper_summary_table.csv",
    label_map: dict[str, str] | None = None,
    digits: int = 3,
) -> Path:
    """Create and write a compact paper-facing summary table."""

    sweep_summary_path = Path(sweep_summary_path)
    output_path = Path(output_path)

    if not sweep_summary_path.exists():
        raise FileNotFoundError(f"Sweep summary not found: {sweep_summary_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    sweep_summary_df = pd.read_csv(sweep_summary_path)
    paper_table = make_paper_summary_table(
        sweep_summary_df,
        label_map=label_map,
        digits=digits,
    )

    paper_table.to_csv(output_path, index=False)

    return output_path


def make_markdown_summary_table(
    sweep_summary_df: pd.DataFrame,
    label_map: dict[str, str] | None = None,
    digits: int = 3,
) -> str:
    """Create a Markdown version of the paper-facing summary table.

    This avoids pandas.DataFrame.to_markdown so that ASTRA does not require the
    optional tabulate dependency.
    """

    paper_table = make_paper_summary_table(
        sweep_summary_df,
        label_map=label_map,
        digits=digits,
    )

    return _dataframe_to_markdown(paper_table, digits=digits)


def write_markdown_summary_table(
    sweep_summary_path: str | Path = "outputs/tables/impairment_sweep_summary.csv",
    output_path: str | Path = "outputs/tables/paper_summary_table.md",
    label_map: dict[str, str] | None = None,
    digits: int = 3,
) -> Path:
    """Create and write a Markdown paper-facing summary table."""

    sweep_summary_path = Path(sweep_summary_path)
    output_path = Path(output_path)

    if not sweep_summary_path.exists():
        raise FileNotFoundError(f"Sweep summary not found: {sweep_summary_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    sweep_summary_df = pd.read_csv(sweep_summary_path)
    markdown_table = make_markdown_summary_table(
        sweep_summary_df,
        label_map=label_map,
        digits=digits,
    )

    output_path.write_text(markdown_table + "\n", encoding="utf-8")

    return output_path

def make_interpretation_summary_table(
    sweep_summary_df: pd.DataFrame,
    label_map: dict[str, str] | None = None,
    interpretation_map: dict[str, dict[str, str]] | None = None,
) -> pd.DataFrame:
    """Create a paper-facing interpretation table for each experiment.

    The table maps each experiment to a compact qualitative interpretation of
    what its delivery-side and usefulness-side metrics demonstrate.
    """

    _require_columns(
        sweep_summary_df,
        {"experiment_slug"},
        "sweep_summary_df",
    )

    label_map = label_map or DEFAULT_EXPERIMENT_LABELS
    interpretation_map = interpretation_map or DEFAULT_EXPERIMENT_INTERPRETATIONS

    rows = []
    for slug in sweep_summary_df["experiment_slug"].astype(str):
        interpretation = interpretation_map.get(
            slug,
            {
                "Delivery-side observation": "Not specified.",
                "Usefulness-side observation": "Not specified.",
                "Interpretation": "No interpretation has been defined.",
            },
        )

        rows.append(
            {
                "Experiment": label_map.get(slug, slug),
                "Delivery-side observation": interpretation[
                    "Delivery-side observation"
                ],
                "Usefulness-side observation": interpretation[
                    "Usefulness-side observation"
                ],
                "Interpretation": interpretation["Interpretation"],
            }
        )

    table = pd.DataFrame(rows)

    return table[INTERPRETATION_SUMMARY_COLUMNS]


def make_markdown_interpretation_table(
    sweep_summary_df: pd.DataFrame,
    label_map: dict[str, str] | None = None,
    interpretation_map: dict[str, dict[str, str]] | None = None,
) -> str:
    """Create a Markdown version of the paper-facing interpretation table."""

    interpretation_table = make_interpretation_summary_table(
        sweep_summary_df,
        label_map=label_map,
        interpretation_map=interpretation_map,
    )

    return _dataframe_to_markdown(interpretation_table)


def write_markdown_interpretation_table(
    sweep_summary_path: str | Path = "outputs/tables/impairment_sweep_summary.csv",
    output_path: str | Path = "outputs/tables/interpretation_summary_table.md",
    label_map: dict[str, str] | None = None,
    interpretation_map: dict[str, dict[str, str]] | None = None,
) -> Path:
    """Create and write a Markdown paper-facing interpretation table."""

    sweep_summary_path = Path(sweep_summary_path)
    output_path = Path(output_path)

    if not sweep_summary_path.exists():
        raise FileNotFoundError(f"Sweep summary not found: {sweep_summary_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    sweep_summary_df = pd.read_csv(sweep_summary_path)
    markdown_table = make_markdown_interpretation_table(
        sweep_summary_df,
        label_map=label_map,
        interpretation_map=interpretation_map,
    )

    output_path.write_text(markdown_table + "\n", encoding="utf-8")

    return output_path