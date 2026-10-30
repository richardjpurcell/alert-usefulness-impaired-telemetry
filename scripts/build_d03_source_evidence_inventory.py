"""D03: Immutable-source evidence inventory for the Mordor Mimikatz scenario.

This independent audit DOES NOT calculate compromise truth, severity, alert
usefulness, or belief updates. It preserves source-event identities and uses
structured Sysmon process-access fields to identify *candidate evidence*.

Requires only the Python standard library. Reads the original NDJSON from the
local source ZIP without extracting or rewriting the archive.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZipFile


DEFAULT_ARCHIVE = Path("data/raw/mordor/empire_mimikatz_logonpasswords.zip")
DEFAULT_OUTPUT = Path("outputs/d03_source_evidence")
DEFAULT_HOST = "WORKSTATION5"
DEFAULT_AGENT_PID = "1648"  # Documented Empire agent PID, not an inferred compromise label.

INVENTORY_COLUMNS = [
    "source_event_id", "source_line", "record_sha256", "host", "event_id",
    "event_time_utc", "event_time_basis", "indexed_at_utc", "record_number",
    "lsass_access", "powershell_lsass_access", "documented_agent_lsass_access",
    "evidence_class",
]
DETAIL_COLUMNS = INVENTORY_COLUMNS + [
    "source_image", "source_process_id", "source_process_guid", "target_image",
    "target_process_id", "target_process_guid", "granted_access", "channel",
]


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def basename(value: Any) -> str:
    """Compare Windows paths on non-Windows systems without OS-specific rules."""
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def normalized_host(value: Any) -> str:
    return str(value or "").split(".", 1)[0].casefold()


def utc_timestamp(value: Any) -> str:
    """Normalize only known UTC fields; never guess the timezone of local fields."""
    if not value:
        return ""
    raw = str(value).strip()
    try:
        timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if timestamp.tzinfo is None:
        # Used ONLY for Sysmon's explicitly UTC-labelled UtcTime field.
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def classify_record(record: dict[str, Any], scenario_host: str, agent_pid: str) -> dict[str, Any]:
    """Three nested indicator definitions. None is a compromise label."""
    try:
        event_id = int(record.get("EventID", -1))
    except (ValueError, TypeError):
        event_id = -1
    lsass = event_id == 10 and basename(record.get("TargetImage")) == "lsass.exe"
    powershell = lsass and basename(record.get("SourceImage")) == "powershell.exe"
    documented = (
        powershell
        and normalized_host(record.get("Hostname")) == normalized_host(scenario_host)
        and str(record.get("SourceProcessId", "")).strip() == str(agent_pid)
    )
    label = (
        "documented_agent_access" if documented else
        "powershell_lsass_access" if powershell else
        "lsass_process_access" if lsass else "none"
    )
    return {
        "lsass_access": int(lsass),
        "powershell_lsass_access": int(powershell),
        "documented_agent_lsass_access": int(documented),
        "evidence_class": label,
    }


def source_event_time(record: dict[str, Any]) -> tuple[str, str]:
    # Sysmon UtcTime is source-side UTC. @timestamp is a pipeline/index time and
    # is explicitly labelled as a fallback, NOT independently known event time.
    if record.get("UtcTime"):
        value = utc_timestamp(record["UtcTime"])
        if value:
            return value, "source_UtcTime"
    if record.get("@timestamp"):
        value = utc_timestamp(record["@timestamp"])
        if value:
            return value, "index_timestamp_fallback"
    return "", "unknown"


def event_rows(record: dict[str, Any], line_no: int, raw_line: bytes, scenario_host: str, agent_pid: str) -> tuple[dict[str, Any], dict[str, Any]]:
    event_time, basis = source_event_time(record)
    try:
        event_id: Any = int(record.get("EventID", -1))
    except (ValueError, TypeError):
        event_id = ""
    base = {
        "source_event_id": f"mordor_empire_mimikatz:{line_no:06d}",
        "source_line": line_no,
        "record_sha256": hashlib.sha256(raw_line.rstrip(b"\r\n")).hexdigest(),
        "host": str(record.get("Hostname") or ""),
        "event_id": event_id,
        "event_time_utc": event_time,
        "event_time_basis": basis,
        "indexed_at_utc": utc_timestamp(record.get("@timestamp")),
        "record_number": str(record.get("RecordNumber") or ""),
        **classify_record(record, scenario_host, agent_pid),
    }
    detail = {**base, **{
        "source_image": str(record.get("SourceImage") or ""),
        "source_process_id": str(record.get("SourceProcessId") or ""),
        "source_process_guid": str(record.get("SourceProcessGUID") or ""),
        "target_image": str(record.get("TargetImage") or ""),
        "target_process_id": str(record.get("TargetProcessId") or ""),
        "target_process_guid": str(record.get("TargetProcessGUID") or ""),
        "granted_access": str(record.get("GrantedAccess") or ""),
        "channel": str(record.get("Channel") or ""),
    }}
    return base, detail


def build_inventory(archive: Path, output_dir: Path, scenario_host: str = DEFAULT_HOST, agent_pid: str = DEFAULT_AGENT_PID) -> dict[str, Any]:
    """Stream the original archive once, producing deterministic CSVs and manifest."""
    if not archive.is_file():
        raise FileNotFoundError(f"Missing raw Mordor archive: {archive}")
    output_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = output_dir / "d03_source_event_inventory.csv"
    evidence_path = output_dir / "d03_lsass_access_evidence.csv"
    manifest_path = output_dir / "d03_evidence_manifest.json"
    counts: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    time_bases: Counter[str] = Counter()
    hash_uncompressed = hashlib.sha256()
    with ZipFile(archive) as zf:
        members = [entry for entry in zf.infolist() if not entry.is_dir() and entry.filename.lower().endswith(".json")]
        if len(members) != 1:
            raise ValueError(f"Expected one NDJSON .json member, found {len(members)}")
        member = members[0]
        # CSV writer uses fixed ordering for deterministic output.
        with (
            zf.open(member) as stream,
            inventory_path.open("w", newline="", encoding="utf-8") as all_file,
            evidence_path.open("w", newline="", encoding="utf-8") as evidence_file,
        ):
            all_writer = csv.DictWriter(all_file, fieldnames=INVENTORY_COLUMNS)
            evidence_writer = csv.DictWriter(evidence_file, fieldnames=DETAIL_COLUMNS)
            all_writer.writeheader()
            evidence_writer.writeheader()
            for line_no, raw_line in enumerate(stream, 1):
                hash_uncompressed.update(raw_line)
                if not raw_line.strip():
                    raise ValueError(f"Blank source line {line_no}; stable line-based IDs require one record per line")
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid NDJSON at source line {line_no}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"Non-object NDJSON record at line {line_no}")
                row, detail = event_rows(record, line_no, raw_line, scenario_host, agent_pid)
                all_writer.writerow(row)
                counts["total_events"] += 1
                hosts[row["host"]] += 1
                time_bases[row["event_time_basis"]] += 1
                for column in ["lsass_access", "powershell_lsass_access", "documented_agent_lsass_access"]:
                    counts[column] += int(row[column])
                if row["lsass_access"]:
                    evidence_writer.writerow(detail)
    if not counts["total_events"]:
        raise ValueError("No source events in archive")
    # Include checksums of OUTPUT files so that a later experiment can enforce
    # reference stability, independently of delivery and aggregation conditions.
    manifest = {
        "experiment": "D03_fixed_source_evidence_inventory",
        "purpose": "fixed evidence reference, not a host-compromise ground truth",
        "scenario": "Empire Mimikatz LogonPasswords",
        "scenario_documentation": "https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-190518202151.html",
        "source_archive": archive.as_posix(),
        "source_archive_sha256": sha256_file(archive),
        "archive_member": member.filename,
        "archive_member_sha256": hash_uncompressed.hexdigest(),
        "selection_parameters": {
            "documented_host": scenario_host,
            "documented_agent_pid": str(agent_pid),
            "source": "OTRF scenario's adversary-view transcript; these are declared association criteria, not incident truth",
        },
        "counts": dict(sorted(counts.items())),
        "hosts": dict(sorted(hosts.items())),
        "event_time_bases": dict(sorted(time_bases.items())),
        "indicator_definitions": {
            "lsass_access": "EventID=10 AND Windows basename(TargetImage)=lsass.exe",
            "powershell_lsass_access": "lsass_access AND basename(SourceImage)=powershell.exe",
            "documented_agent_lsass_access": "powershell_lsass_access AND short Hostname=declared host AND SourceProcessId=declared agent PID",
        },
        "caveats": [
            "These are structured telemetry indicators, not proof of compromise or successful credential extraction.",
            "The documented-agent match is a declared correspondence to an adversary-emulation transcript, not an independently validated event label.",
            "Original @timestamp is retained separately; where UtcTime is absent, event_time_utc is a labelled index-time fallback.",
            "The raw archive and all source-event IDs must stay fixed in subsequent impairment and aggregation comparisons.",
        ],
        "outputs": {
            "inventory": inventory_path.as_posix(),
            "inventory_sha256": sha256_file(inventory_path),
            "evidence": evidence_path.as_posix(),
            "evidence_sha256": sha256_file(evidence_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--documented-host", default=DEFAULT_HOST)
    parser.add_argument("--documented-agent-pid", default=DEFAULT_AGENT_PID)
    args = parser.parse_args()
    manifest = build_inventory(args.archive, args.output_dir, args.documented_host, args.documented_agent_pid)
    print(json.dumps({"counts": manifest["counts"], "hosts": manifest["hosts"], "outputs": manifest["outputs"]}, indent=2))


if __name__ == "__main__":
    main()
