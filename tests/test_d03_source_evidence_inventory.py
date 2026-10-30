"""Contract tests for the independent D03 source-evidence inventory."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
from zipfile import ZipFile

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_d03_source_evidence_inventory.py"
spec = importlib.util.spec_from_file_location("d03_source_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
d03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d03)


def event(**kwargs):
    return {
        "EventID": 10,
        "Hostname": "WORKSTATION5.theshire.local",
        "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "SourceProcessId": "1648",
        "TargetImage": r"C:\Windows\system32\lsass.exe",
        "UtcTime": "2020-08-07 14:32:56.540",
        "@timestamp": "2020-08-07T14:32:57.589Z",
        **kwargs,
    }


def test_structured_match_and_transcript_association():
    evidence = d03.classify_record(event(), "WORKSTATION5", "1648")
    assert evidence == {
        "lsass_access": 1,
        "powershell_lsass_access": 1,
        "documented_agent_lsass_access": 1,
        "evidence_class": "documented_agent_access",
    }


def test_message_keyword_does_not_create_evidence():
    record = event(EventID=4624, Message="Mentioned LSASS.EXE in a note")
    assert d03.classify_record(record, "WORKSTATION5", "1648")["lsass_access"] == 0


def test_other_lsass_access_is_retained_but_not_agent_match():
    record = event(SourceImage=r"C:\Windows\svchost.exe", SourceProcessId="452")
    result = d03.classify_record(record, "WORKSTATION5", "1648")
    assert result["lsass_access"] == 1
    assert result["powershell_lsass_access"] == 0
    assert result["documented_agent_lsass_access"] == 0


def test_agent_match_requires_host_and_pid():
    assert d03.classify_record(event(Hostname="WORKSTATION6.theshire.local"), "WORKSTATION5", "1648")["documented_agent_lsass_access"] == 0
    assert d03.classify_record(event(SourceProcessId="3172"), "WORKSTATION5", "1648")["documented_agent_lsass_access"] == 0


def test_time_provenance_is_not_silently_conflated():
    assert d03.source_event_time(event()) == ("2020-08-07T14:32:56.540Z", "source_UtcTime")
    record = event()
    del record["UtcTime"]
    assert d03.source_event_time(record) == ("2020-08-07T14:32:57.589Z", "index_timestamp_fallback")


def test_zip_integration_determinism_and_original_line_identity(tmp_path):
    archive = tmp_path / "source.zip"
    records = [event(), event(SourceImage=r"C:\Windows\svchost.exe", SourceProcessId="452"), event(EventID=4624, Message="lsass.exe")]
    with ZipFile(archive, "w") as zf:
        zf.writestr("events.json", "".join(json.dumps(r) + "\n" for r in records))
    output = tmp_path / "out"
    first = d03.build_inventory(archive, output)
    with (output / "d03_source_event_inventory.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    with (output / "d03_lsass_access_evidence.csv").open(newline="", encoding="utf-8") as stream:
        relevant = list(csv.DictReader(stream))
    assert [r["source_line"] for r in rows] == ["1", "2", "3"]
    assert len(set(r["source_event_id"] for r in rows)) == 3
    assert len(relevant) == 2
    assert first["counts"]["documented_agent_lsass_access"] == 1
    assert first["counts"]["total_events"] == 3
    assert first == d03.build_inventory(archive, output)


def test_malformed_lines_fail_instead_of_shifting_source_ids(tmp_path):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("events.json", json.dumps(event()) + "\n\n")
    with pytest.raises(ValueError, match="Blank source line 2"):
        d03.build_inventory(archive, tmp_path / "out")
