# Dataset adapter interface

ASTRA now separates dataset-specific parsing from the core usefulness pipeline.

The intended flow is:

```text
raw security dataset
    → extracted event table
    → normalized ASTRA telemetry schema
    → impairment layer
    → defender belief update
    → usefulness diagnostics
    → reporting / figures
```

## Purpose

The dataset adapter interface allows ASTRA to ingest external security telemetry without changing the impairment, belief, metric, reporting, or visualization code.

This is important because real security datasets differ in file format, event schema, timestamp conventions, host identifiers, and attack annotations. ASTRA should not assume that Mordor, OTRF, CIC, LANL, or synthetic telemetry use the same raw structure. Instead, each dataset should be mapped into a stable normalized telemetry schema.

## Normalized telemetry schema

The current normalized telemetry columns are:

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

These columns provide the minimum event representation needed for ASTRA to reason about telemetry usefulness.

`event_id` identifies the normalized event.

`event_time` records the event timestamp or ordered event time.

`host_id` identifies the host, user, endpoint, or system entity being observed.

`event_type` records the alert, log, or event category.

`severity` records a numeric or categorical indication of event importance.

`observed_state` records the security-state observation implied by the event, such as benign, suspicious, or compromised.

`source_dataset` identifies the dataset family, such as synthetic or mordor.

`scenario` identifies the specific experiment or adversary-emulation scenario.

## Generic adapter

The generic adapter accepts an input event table and a column map. The column map tells ASTRA how to translate source columns into the normalized telemetry schema.

Example:

```python
{
    "event_time": "timestamp",
    "host_id": "hostname",
    "event_type": "category",
    "severity": "risk_score",
    "observed_state": "state",
}
```

This makes the adapter reusable for simple CSV exports, synthetic tables, and extracted real-data event tables.

## Mordor / OTRF adapter scaffold

The Mordor adapter currently targets a simplified Mordor-like extracted event table, not raw Mordor JSON or the full OTRF repository structure.

The default Mordor-like mapping is:

```python
{
    "event_time": "timestamp",
    "host_id": "host",
    "event_type": "event_type",
    "severity": "severity",
    "observed_state": "observed_state",
}
```

This deliberately keeps the first real-data step narrow:

```text
raw Mordor / OTRF logs
    → extracted Mordor-like event table
    → normalized ASTRA telemetry schema
```

Later branches can add raw JSON parsing, ATT&CK metadata handling, scenario manifests, and dataset-specific extraction scripts.

## Design principle

Dataset adapters should translate external telemetry into ASTRA’s schema. They should not implement impairment logic, belief updates, usefulness classification, reporting, or plotting.

This keeps the ASTRA pipeline modular:

```text
dataset parsing is replaceable
core usefulness logic is stable
experiments remain reproducible
```

## Current status

Implemented:

```text
src/astra/datasets.py
tests/test_datasets.py
```

Current capabilities:

```text
require_normalized_telemetry_columns
normalize_generic_event_table
load_generic_event_csv
normalize_mordor_event_table
load_mordor_event_csv
```

The project is ready for a first real-data import branch using one extracted Mordor / OTRF scenario.
