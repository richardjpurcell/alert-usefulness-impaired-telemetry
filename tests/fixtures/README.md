# Test fixtures

This directory contains small committed data fixtures used by the ASTRA test
suite.

## `mordor_sample_events.csv`

This file is a Mordor-like event fixture used to exercise ASTRA's dataset
adapter interface.

It is **not** a real Mordor / OTRF extract.

The fixture is intentionally small and synthetic-looking. Its purpose is to
verify that the Mordor adapter can load an event CSV with the expected
intermediate schema:

```text
timestamp
host
event_type
severity
observed_state
```

The adapter then normalizes those fields into ASTRA's internal telemetry schema:

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

This fixture supports the development path:

```text
Mordor-like fixture
    → normalized ASTRA telemetry schema
    → future real Mordor / OTRF scenario import
```

A later branch should replace or supplement this fixture with a documented
extracted event table from an actual Mordor / OTRF scenario.


