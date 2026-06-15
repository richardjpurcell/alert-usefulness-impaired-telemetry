# Empire Mimikatz extraction summary

This note summarizes ASTRA's first real Mordor / OTRF extraction path.

## Scenario

Scenario:

```text
Empire Mimikatz LogonPasswords
```

ASTRA scenario slug:

```text
empire_mimikatz_logonpasswords
```

Source dataset family:

```text
Mordor / OTRF Security Datasets
```

## Extractor

Extractor script:

```text
scripts/extract_mordor_empire_mimikatz.py
```

The script reads the locally downloaded Mordor / OTRF NDJSON file and writes a compact ASTRA-ready intermediate CSV.

Default input path:

```text
data/raw/mordor/empire_mimikatz_logonpasswords/empire_mimikatz_logonpasswords_2020-08-07103224.json
```

Default output path:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

The raw and processed data directories are ignored by git.

## Local extraction result

The local extraction produced:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

Observed local output size:

```text
528K
```

Extracted record count:

```text
6,026 events
```

The extracted CSV uses ASTRA's Mordor-like intermediate schema:

```text
timestamp
host
event_type
severity
observed_state
```

Example rows from the extracted file:

```text
timestamp,host,event_type,severity,observed_state
2020-08-07T14:32:25.358Z,MORDORDC.theshire.local,sysmon_process_access,medium,suspicious
2020-08-07T14:32:25.359Z,MORDORDC.theshire.local,sysmon_process_access,medium,suspicious
2020-08-07T14:32:25.359Z,MORDORDC.theshire.local,sysmon_process_access,medium,suspicious
2020-08-07T14:32:25.359Z,WORKSTATION5.theshire.local,registry_change,medium,suspicious
```

## Mapping rules

The extractor derives:

```text
timestamp      ← @timestamp, falling back to UtcTime
host           ← Hostname
event_type     ← EventID and channel/source fallback rules
severity       ← scenario-specific ASTRA severity rule
observed_state ← scenario-specific ASTRA observed-state rule
```

Current event-type examples include:

```text
powershell_pipeline
powershell_module
sysmon_process_access
sysmon_network_connection
security_object_access
security_handle_request
security_handle_closed
security_logon
registry_change
file_create
image_load
other_security_event
other_sysmon_event
other_event
```

Current observed-state values are:

```text
benign
suspicious
compromised
```

Current severity values are:

```text
low
medium
high
```

## Current interpretation

This extraction is not yet a full ASTRA experiment. It is the first real-data bridge:

```text
raw Mordor / OTRF NDJSON
    → extracted ASTRA-ready event CSV
    → load_mordor_event_csv
    → normalized ASTRA telemetry
```

The important result is that ASTRA can now produce a compact event table from a real Mordor / OTRF scenario without changing the impairment, belief, metric, reporting, or visualization modules.

## Limitations

The extraction rules are first-pass and scenario-specific.

They should not be treated as a general Mordor parser, a complete Windows event taxonomy, or SOC-grade ground truth.

The current mapping is an ASTRA experimental abstraction designed to support the question:

```text
When does delivered security telemetry improve a defender's belief state,
and when does it become stale, misleading, redundant, or workload-generating?
```

## Next step

The next implementation step should prove that the extracted CSV loads through ASTRA's dataset adapter:

```text
load_mordor_event_csv
```

and then create a small test fixture or summary check showing:

```text
real extracted scenario CSV
    → normalized ASTRA telemetry DataFrame
```

After that, ASTRA can begin running impairment experiments over the extracted Mordor event stream.

