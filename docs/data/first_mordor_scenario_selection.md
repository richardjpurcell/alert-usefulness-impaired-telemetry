# First Mordor / OTRF scenario selection

This note selects the first real Mordor / OTRF scenario for ASTRA import.

The current ASTRA repository already contains:

```text
tests/fixtures/mordor_sample_events.csv
```

That fixture is Mordor-like, but it is not a real Mordor / OTRF extract. The purpose of this note is to define the first actual scenario target before writing import code.

## Selected scenario

Selected first scenario:

```text
Empire Mimikatz LogonPasswords
```

Working ASTRA scenario slug:

```text
empire_mimikatz_logonpasswords
```

Expected Mordor / OTRF query-style name:

```text
small.windows.credential_access.host.empire_mimikatz_logonpasswords
```

Expected repository path pattern:

```text
datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip
```

## Why this scenario

This is a suitable first ASTRA real-data scenario because it is:

```text
small
Windows-focused
host-event focused
credential-access focused
associated with a clear adversary action
likely to contain timestamped security events
easier to inspect than a broad multi-stage campaign
```

The scenario represents adversaries reading credentials from LSASS memory using Mimikatz. That makes it a good fit for ASTRA because the incident-state abstraction can be simple:

```text
benign
suspicious
compromised
```

The scenario is also narrow enough that the first import can focus on the dataset-adapter problem rather than on full attack reconstruction.

## Source-data expectation

The first implementation branch should expect one downloadable host-event dataset archive associated with the selected scenario.

The raw data may be JSON, JSONL, CSV, or another event-export format contained inside the downloaded archive.

ASTRA should not assume that all Mordor / OTRF scenarios have the same raw shape. The first implementation should inspect this scenario only and create an extracted intermediate event table.

## Extraction target

The extraction target is a Mordor-like event table with the columns already supported by ASTRA:

```text
timestamp
host
event_type
severity
observed_state
```

This extracted table is the boundary between Mordor-specific parsing and ASTRA's normalized telemetry schema.

## ASTRA normalized schema

The extracted table should load through:

```text
load_mordor_event_csv
```

and normalize into:

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

For this scenario:

```text
source_dataset = mordor
scenario = empire_mimikatz_logonpasswords
```

## Initial observed_state mapping plan

The first mapping should be conservative and documented.

Use:

```text
benign
suspicious
compromised
```

Proposed initial interpretation:

```text
benign
    Routine or background event not directly tied to the credential-access action.

suspicious
    Event plausibly associated with the Mimikatz / credential-access activity,
    but not by itself sufficient to represent a compromised state.

compromised
    Event strongly associated with credential dumping, LSASS access, or
    post-compromise activity in the selected scenario.
```

This mapping is an ASTRA abstraction. It should not be presented as universal security ground truth.

## Initial severity mapping plan

Use a simple categorical severity scale:

```text
low
medium
high
```

Proposed initial mapping:

```text
low
    Routine background event.

medium
    Suspicious event or supporting activity.

high
    Event strongly associated with credential access or compromise.
```

If the raw dataset already contains useful severity-like fields, the implementation branch can preserve or adapt them. If not, severity should be assigned by a documented scenario-specific rule.

## What files should not be committed yet

Do not commit large raw Mordor / OTRF archives unless they are small, license-compatible, and clearly appropriate for the repository.

Prefer this structure:

```text
data/raw/
    not committed, or documented download location only

data/processed/
    small extracted event table only if appropriate

docs/data/
    extraction notes and assumptions

tests/fixtures/
    tiny representative fixture for tests
```

## First implementation branch target

The next implementation branch should do only this:

```text
download or locate the selected scenario
inspect the raw archive contents
identify timestamp, host, event-type, and useful event fields
create a small extracted event table
document observed_state and severity mappings
prove the extracted table loads through load_mordor_event_csv
```

It should not attempt:

```text
full Mordor / OTRF ingestion
general raw JSON parser
multi-scenario benchmark
complete ATT&CK modeling
automatic ground-truth reconstruction
SOC-grade alert semantics
```

## Success criterion

The first real-data import succeeds when ASTRA can show:

```text
real Mordor / OTRF host-event scenario
    → extracted event table
    → normalized ASTRA telemetry
```

without changing the impairment, belief, metric, reporting, or visualization pipeline.

## Reproducibility notes to record later

The implementation branch should record:

```text
dataset page or repository location
download date
archive filename
files extracted
raw field names used
number of raw events inspected
number of extracted events
observed_state mapping
severity mapping
known limitations
```

This preserves the distinction between:

```text
Mordor-like fixture
first real Mordor / OTRF scenario import
general Mordor / OTRF support
```
