import pandas as pd

from scripts.validate_mordor_extracted_telemetry import (
    DEFAULT_SCENARIO,
    summarize_normalized_telemetry,
)


def test_summarize_normalized_telemetry_loads_extracted_csv(tmp_path):
    input_path = tmp_path / "empire_mimikatz_logonpasswords_events.csv"

    pd.DataFrame(
        [
            {
                "timestamp": "2020-08-07T14:32:25.358Z",
                "host": "WORKSTATION5.theshire.local",
                "event_type": "powershell_pipeline",
                "severity": "medium",
                "observed_state": "suspicious",
            },
            {
                "timestamp": "2020-08-07T14:33:25.358Z",
                "host": "MORDORDC.theshire.local",
                "event_type": "sysmon_process_access",
                "severity": "high",
                "observed_state": "compromised",
            },
        ]
    ).to_csv(input_path, index=False)

    summary = summarize_normalized_telemetry(input_path)

    assert summary["rows"] == 2
    assert summary["source_datasets"] == ["mordor"]
    assert summary["scenarios"] == [DEFAULT_SCENARIO]
    assert summary["hosts"] == [
        "MORDORDC.theshire.local",
        "WORKSTATION5.theshire.local",
    ]
    assert summary["event_types"] == {
        "powershell_pipeline": 1,
        "sysmon_process_access": 1,
    }
    assert summary["severity"] == {
        "medium": 1,
        "high": 1,
    }
    assert summary["observed_state"] == {
        "suspicious": 1,
        "compromised": 1,
    }