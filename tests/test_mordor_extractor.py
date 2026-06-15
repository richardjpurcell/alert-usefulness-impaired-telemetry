import json

import pandas as pd
import pytest

from scripts.extract_mordor_empire_mimikatz import (
    derive_event_type,
    derive_observed_state,
    derive_severity,
    extract_events,
    write_extracted_events,
)


def test_derive_event_type_maps_known_event_ids():
    assert derive_event_type({"EventID": 800}) == "powershell_pipeline"
    assert derive_event_type({"EventID": 4103}) == "powershell_module"
    assert derive_event_type({"EventID": 10}) == "sysmon_process_access"
    assert derive_event_type({"EventID": 4663}) == "security_object_access"


def test_derive_event_type_uses_channel_fallbacks():
    assert (
        derive_event_type({"EventID": 9999, "Channel": "Windows PowerShell"})
        == "powershell_event"
    )
    assert (
        derive_event_type({"EventID": 9999, "Channel": "Security"})
        == "other_security_event"
    )
    assert (
        derive_event_type(
            {
                "EventID": 9999,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            }
        )
        == "other_sysmon_event"
    )


def test_derive_observed_state_marks_lsass_as_compromised():
    record = {
        "EventID": 10,
        "TargetImage": r"C:\windows\system32\lsass.exe",
    }

    assert derive_observed_state(record) == "compromised"


def test_derive_observed_state_marks_powershell_as_suspicious():
    record = {
        "EventID": 800,
        "Message": "PowerShell pipeline execution details",
    }

    assert derive_observed_state(record) == "suspicious"


def test_derive_observed_state_defaults_to_benign():
    assert derive_observed_state({"EventID": 9999, "Message": "Routine event"}) == "benign"


def test_derive_severity_follows_observed_state():
    assert derive_severity({"TargetImage": "lsass.exe"}, "compromised") == "high"
    assert derive_severity({"EventID": 800}, "suspicious") == "medium"
    assert derive_severity({"EventID": 9999}, "benign") == "low"


def test_extract_events_reads_ndjson(tmp_path):
    input_path = tmp_path / "events.json"

    records = [
        {
            "@timestamp": "2020-08-07T14:32:25.358Z",
            "Hostname": "WORKSTATION5.theshire.local",
            "EventID": 800,
            "Channel": "Windows PowerShell",
            "Message": "PowerShell pipeline execution details",
        },
        {
            "@timestamp": "2020-08-07T14:33:25.358Z",
            "Hostname": "MORDORDC.theshire.local",
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "TargetImage": r"C:\windows\system32\lsass.exe",
        },
    ]

    with input_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    extracted = extract_events(input_path)

    assert list(extracted.columns) == [
        "timestamp",
        "host",
        "event_type",
        "severity",
        "observed_state",
    ]
    assert len(extracted) == 2

    assert extracted.loc[0, "host"] == "WORKSTATION5.theshire.local"
    assert extracted.loc[0, "event_type"] == "powershell_pipeline"
    assert extracted.loc[0, "severity"] == "medium"
    assert extracted.loc[0, "observed_state"] == "suspicious"

    assert extracted.loc[1, "host"] == "MORDORDC.theshire.local"
    assert extracted.loc[1, "event_type"] == "sysmon_process_access"
    assert extracted.loc[1, "severity"] == "high"
    assert extracted.loc[1, "observed_state"] == "compromised"


def test_extract_events_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="Mordor NDJSON file not found"):
        extract_events(tmp_path / "missing.json")


def test_write_extracted_events_writes_csv(tmp_path):
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "events.csv"

    record = {
        "@timestamp": "2020-08-07T14:32:25.358Z",
        "Hostname": "WORKSTATION5.theshire.local",
        "EventID": 800,
        "Channel": "Windows PowerShell",
        "Message": "PowerShell pipeline execution details",
    }

    input_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    written = write_extracted_events(input_path=input_path, output_path=output_path)

    assert written == output_path
    assert output_path.exists()

    loaded = pd.read_csv(output_path)

    assert len(loaded) == 1
    assert loaded.loc[0, "event_type"] == "powershell_pipeline"
    assert loaded.loc[0, "observed_state"] == "suspicious"