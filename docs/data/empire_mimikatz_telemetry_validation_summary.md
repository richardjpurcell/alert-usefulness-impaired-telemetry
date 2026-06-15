# Empire Mimikatz telemetry validation summary

This note records the first successful validation of real extracted Mordor / OTRF telemetry through ASTRA's dataset adapter.

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

## Validation script

Validation script:

```text
scripts/validate_mordor_extracted_telemetry.py
```

The script loads the locally generated extracted CSV:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

through ASTRA's Mordor adapter:

```text
load_mordor_event_csv
```

and summarizes the normalized telemetry dataframe.

## Validation result

The extracted telemetry successfully loaded into ASTRA's normalized telemetry schema.

Normalized columns:

```text
event_id
event_time
host_id
event_type
severity
observed_state
source_dataset
scenario
```

Row count:

```text
6,026
```

Source dataset:

```text
mordor
```

Scenario:

```text
empire_mimikatz_logonpasswords
```

Hosts:

```text
MORDORDC.theshire.local
WORKSTATION5.theshire.local
WORKSTATION6.theshire.local
```

## Event-type distribution

```text
powershell_pipeline          2,940
powershell_module            1,695
other_security_event           514
sysmon_process_access          272
registry_change                199
sysmon_network_connection       90
security_handle_closed          86
image_load                      81
security_handle_request         49
security_object_access          43
other_sysmon_event              23
file_create                     14
security_logon                  10
powershell_event                 9
other_event                      1
```

## Severity distribution

```text
medium    5,460
low         336
high        230
```

## Observed-state distribution

```text
suspicious     5,460
benign           336
compromised      230
```

## Interpretation

This validates the first real-data bridge in ASTRA:

```text
raw Mordor / OTRF NDJSON
    → extracted ASTRA-ready event CSV
    → load_mordor_event_csv
    → normalized ASTRA telemetry dataframe
```

The result does not yet constitute a full impairment experiment. It shows that a real Mordor / OTRF event stream can be normalized into ASTRA's telemetry schema without changing the impairment, belief, metric, reporting, or visualization modules.

## Why this matters

ASTRA began with controlled synthetic telemetry so that the core distinction could be tested cleanly:

```text
security telemetry that arrives is not always useful
```

This validation step shows that the same scaffold can now accept a real adversary-emulation dataset. The next stage can therefore test impairments such as delay, loss, noise, duplication, flood, and suppression on an extracted Mordor event stream.

## Limitations

The current extraction and mapping rules are first-pass and scenario-specific.

The labels:

```text
benign
suspicious
compromised
```

and severity levels:

```text
low
medium
high
```

are ASTRA experimental abstractions. They are not universal ground truth, not a complete Windows event taxonomy, and not SOC-grade alert semantics.

The processed CSV is generated locally and ignored by git. The repository commits the extractor, validation script, tests, and documentation, but not the raw or processed dataset files.

## Next step

The next implementation step should create a small Mordor-based ASTRA experiment path:

```text
normalized Mordor telemetry
    → controlled impairment
    → defender belief update
    → usefulness diagnostics
```

A narrow first experiment should use the extracted `observed_state` values as the event stream and compare at least:

```text
healthy
delay
loss
noise
alert flood
suppression
```

The goal is not yet to claim operational security validity. The goal is to show that ASTRA's synthetic impairment logic can be applied to a real extracted security telemetry stream.
