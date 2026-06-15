"""Extract ASTRA-ready events from the Mordor Empire Mimikatz scenario.

This script reads the locally downloaded Mordor / OTRF NDJSON file for the
Empire Mimikatz LogonPasswords scenario and writes a compact intermediate CSV
with ASTRA's Mordor-like schema:

    timestamp, host, event_type, severity, observed_state

The raw Mordor archive is intentionally not committed. Expected local input:

    data/raw/mordor/empire_mimikatz_logonpasswords/
        empire_mimikatz_logonpasswords_2020-08-07103224.json

Default output:

    data/processed/empire_mimikatz_logonpasswords_events.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd


DEFAULT_INPUT_PATH = Path(
    "data/raw/mordor/empire_mimikatz_logonpasswords/"
    "empire_mimikatz_logonpasswords_2020-08-07103224.json"
)

DEFAULT_OUTPUT_PATH = Path(
    "data/processed/empire_mimikatz_logonpasswords_events.csv"
)


EVENT_TYPE_MAP = {
    800: "powershell_pipeline",
    4103: "powershell_module",
    10: "sysmon_process_access",
    3: "sysmon_network_connection",
    4663: "security_object_access",
    4656: "security_handle_request",
    4658: "security_handle_closed",
    4624: "security_logon",
    12: "registry_change",
    13: "registry_change",
    11: "file_create",
    7: "image_load",
}


SUSPICIOUS_EVENT_IDS = {
    800,
    4103,
    10,
    3,
    12,
    13,
    4656,
    4658,
    4663,
    4690,
}


def _lower_text(*values: Any) -> str:
    """Join values into a lower-case searchable text blob."""

    return " ".join(str(value).lower() for value in values if value is not None)


def derive_event_type(record: dict[str, Any]) -> str:
    """Derive a compact ASTRA-facing event type from a Mordor record."""

    event_id = record.get("EventID")
    channel = str(record.get("Channel", "")).lower()
    source_name = str(record.get("SourceName", "")).lower()

    if event_id in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[event_id]

    if "powershell" in channel or "powershell" in source_name:
        return "powershell_event"

    if "security" in channel or "security" in source_name:
        return "other_security_event"

    if "sysmon" in channel or "sysmon" in source_name:
        return "other_sysmon_event"

    return "other_event"


def derive_observed_state(record: dict[str, Any]) -> str:
    """Derive ASTRA's simplified observed state for one record."""

    event_id = record.get("EventID")
    text = _lower_text(
        record.get("Message"),
        record.get("SourceImage"),
        record.get("TargetImage"),
        record.get("CommandLine"),
        record.get("Image"),
    )

    if "lsass.exe" in text:
        return "compromised"

    if event_id in SUSPICIOUS_EVENT_IDS or "powershell" in text:
        return "suspicious"

    return "benign"


def derive_severity(record: dict[str, Any], observed_state: str) -> str:
    """Derive a simple ASTRA severity label."""

    event_id = record.get("EventID")
    text = _lower_text(
        record.get("Message"),
        record.get("SourceImage"),
        record.get("TargetImage"),
        record.get("CommandLine"),
        record.get("Image"),
    )

    if observed_state == "compromised" or "lsass.exe" in text:
        return "high"

    if observed_state == "suspicious" or event_id in SUSPICIOUS_EVENT_IDS:
        return "medium"

    return "low"


def extract_record(record: dict[str, Any]) -> dict[str, str]:
    """Extract one Mordor record into ASTRA's intermediate event schema."""

    observed_state = derive_observed_state(record)

    return {
        "timestamp": str(record.get("@timestamp") or record.get("UtcTime") or ""),
        "host": str(record.get("Hostname") or ""),
        "event_type": derive_event_type(record),
        "severity": derive_severity(record, observed_state),
        "observed_state": observed_state,
    }


def extract_events(input_path: str | Path) -> pd.DataFrame:
    """Extract a Mordor NDJSON file into ASTRA's Mordor-like event table."""

    input_path = Path(input_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Mordor NDJSON file not found: {input_path}")

    rows = []
    with input_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            record = json.loads(line)
            rows.append(extract_record(record))

    return pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "host",
            "event_type",
            "severity",
            "observed_state",
        ],
    )


def write_extracted_events(
    input_path: str | Path = DEFAULT_INPUT_PATH,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
) -> Path:
    """Extract and write the Mordor-like event CSV."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    extracted = extract_events(input_path)
    extracted.to_csv(output_path, index=False)

    return output_path


def main() -> None:
    """Run the extractor from the command line."""

    parser = argparse.ArgumentParser(
        description="Extract ASTRA-ready events from Mordor Empire Mimikatz NDJSON."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Path to raw Mordor NDJSON file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Path to write extracted ASTRA-ready CSV.",
    )

    args = parser.parse_args()

    output_path = write_extracted_events(
        input_path=args.input,
        output_path=args.output,
    )

    print(output_path)


if __name__ == "__main__":
    main()