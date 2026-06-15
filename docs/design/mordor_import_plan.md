# Mordor / OTRF import plan

This note defines the boundary for ASTRA's first real Mordor / OTRF import.

The current repository contains a Mordor-like fixture:

```text
tests/fixtures/mordor_sample_events.csv
```

That fixture is intentionally not a real Mordor / OTRF extract. It exists only to test the adapter interface. The next step is to import one documented real scenario in a controlled, reproducible way.

## Goal

Create the first real-data path from a Mordor / OTRF scenario into ASTRA's normalized telemetry schema.

The target flow is:

```text
raw Mordor / OTRF scenario data
    → extracted event table
    → normalized ASTRA telemetry schema
    → impairment layer
    → defender belief update
    → usefulness diagnostics
```

## First target scenario

The first target should be a small, well-documented Mordor / OTRF adversary-emulation scenario with timestamped host or security events.

Preferred properties:

```text
small enough to inspect manually
host-level events available
clear attack narrative or scenario description
timestamps available
event categories available
some mapping to suspicious or compromised activity possible
```

The first import does not need broad dataset coverage. One scenario is enough.

## Expected raw source format

The raw Mordor / OTRF material may appear as JSON, JSONL, CSV, exported logs, or repository-hosted event records.

ASTRA should not assume the raw structure is stable across all Mordor / OTRF scenarios. Instead, the first extraction should create an intermediate event table.

## Extraction target

The first extraction target is a Mordor-like event table with these columns:

```text
timestamp
host
event_type
severity
observed_state
```

This intermediate table is the boundary between dataset-specific extraction and ASTRA's core pipeline.

## Normalized ASTRA telemetry schema

The Mordor adapter then maps the extracted table into:

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

For the first real import:

```text
source_dataset = mordor
scenario = short documented scenario slug
```

## Assigning `observed_state`

The `observed_state` field is a simplified security-state observation used by ASTRA's belief pipeline.

For the first import, use a deliberately conservative mapping:

```text
benign        routine or background event
suspicious    event plausibly associated with adversary activity
compromised   event strongly associated with compromise or post-compromise action
```

The mapping should be documented beside the extracted event table. It should not be presented as ground truth for all security interpretation. It is a scenario-specific abstraction for the ASTRA experiment.

## Assigning `severity`

For the first import, severity may be categorical:

```text
low
medium
high
```

or numeric if the source already provides a score.

If the raw data does not provide severity, ASTRA may assign a simple scenario-specific severity based on event type, but this rule must be documented.

## What this branch should not attempt

The first real Mordor / OTRF import should not attempt:

```text
full OTRF repository ingestion
general Mordor JSON parser
complete ATT&CK technique modeling
multi-scenario benchmark
automatic ground-truth reconstruction
production SOC alert semantics
```

The goal is only to prove that one real adversary-emulation scenario can be converted into ASTRA's normalized telemetry schema.

## Expected outputs of the first real import branch

A later implementation branch should add:

```text
data/external/ or data/raw/ instructions, if raw data is not committed
data/processed/<scenario>_events.csv, if small and license-compatible
docs/data/<scenario>_extraction.md
tests/fixtures/<scenario>_sample_events.csv or a small representative fixture
tests proving the extracted table loads through load_mordor_event_csv
```

Large raw datasets should not be committed unless they are small, license-compatible, and appropriate for the repository.

## Reproducibility note

The extraction process should record:

```text
dataset source
scenario name
download or access date
source file names
extraction assumptions
observed_state mapping
severity mapping
known limitations
```

This keeps ASTRA honest about the difference between:

```text
Mordor-like fixture
real extracted Mordor / OTRF event table
general Mordor / OTRF dataset support
```
