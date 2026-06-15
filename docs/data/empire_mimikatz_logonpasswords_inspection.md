# Empire Mimikatz LogonPasswords inspection note

This note records the initial inspection plan for ASTRA's first real Mordor / OTRF scenario import.

## Scenario

Selected scenario:

```text
Empire Mimikatz LogonPasswords
```

ASTRA scenario slug:

```text
empire_mimikatz_logonpasswords
```

Expected query-style name:

```text
small.windows.credential_access.host.empire_mimikatz_logonpasswords
```

Expected dataset path pattern:

```text
datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip
```

## Source context

The Security Datasets page describes this scenario as adversaries reading credentials from the memory contents of `lsass.exe`, with Mimikatz given as a common tool for this behavior. The page lists the tactic as `TA0006` and the technique as `T1003.001`, with the tag `LSASS Memory Credentials Read`. The metadata lists Roberto Rodriguez as contributor, with creation date `2019/05/18` and modification date `2020/09/20`.

MSTICPy documents a Mordor / OTRF data provider that can browse and query Mordor datasets and return results as pandas DataFrames. This is relevant because ASTRA's adapter path is also DataFrame-based.

## Purpose of this inspection

The goal is not to build a general Mordor parser yet.

The goal is to inspect one selected scenario and identify how to extract a small event table that ASTRA can normalize.

Target flow:

```text
Empire Mimikatz LogonPasswords raw dataset
    → extracted scenario event table
    → ASTRA normalized telemetry schema
    → impairment / belief / usefulness pipeline
```

## Expected raw material

The scenario is expected to provide host-event data, likely packaged as a downloadable archive.

The raw event material may include JSON, JSONL, CSV, or another exported event format. The implementation branch should inspect the archive contents before assuming a schema.

## Extraction target

The first extracted event table should use ASTRA's Mordor-like intermediate schema:

```text
timestamp
host
event_type
severity
observed_state
```

This intermediate table should then load through:

```text
load_mordor_event_csv
```

and normalize to:

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

## Candidate timestamp field

Candidate raw timestamp fields to look for:

```text
@timestamp
TimeCreated
UtcTime
EventTime
timestamp
```

The extracted table should use a single normalized column:

```text
timestamp
```

If multiple timestamps are available, prefer the event occurrence time rather than ingestion or archive-processing time.

## Candidate host field

Candidate raw host fields to look for:

```text
host
Computer
ComputerName
Hostname
host.name
winlog.computer_name
```

The extracted table should use:

```text
host
```

## Candidate event-type field

Candidate raw event-type fields to look for:

```text
EventID
event_id
event.code
Channel
ProviderName
Task
Image
CommandLine
```

For ASTRA's first import, `event_type` can be a compact label derived from the most useful available fields.

Examples:

```text
process_creation
lsass_access
powershell_execution
security_event_4663
sysmon_event_10
```

The mapping should be documented in the extraction note.

## Candidate severity mapping

Use ASTRA's simple categorical scale:

```text
low
medium
high
```

Initial severity rule:

```text
low
    Background event not directly tied to the credential-access action.

medium
    Suspicious supporting event, such as PowerShell or process activity that may be part of execution context.

high
    Event strongly associated with credential access, LSASS access, Mimikatz execution, or post-compromise credential dumping behavior.
```

The implementation branch should refine this after inspecting the real fields.

## Candidate observed_state mapping

Use ASTRA's simple state observation vocabulary:

```text
benign
suspicious
compromised
```

Initial observed-state rule:

```text
benign
    Routine or background event not directly tied to the credential-access action.

suspicious
    Event plausibly associated with the Mimikatz / credential-access activity,
    but not sufficient on its own to represent compromise.

compromised
    Event strongly associated with LSASS memory access, credential dumping,
    Mimikatz execution, or post-compromise credential access.
```

This is an ASTRA abstraction for the experiment. It is not universal security ground truth.

## Expected indicators to inspect

Because the scenario concerns reading LSASS memory, the extraction should look for evidence such as:

```text
process creation events
PowerShell execution
Mimikatz-related command lines or module names
access to lsass.exe
Sysmon process access events
Windows Security object access events
credential dumping indicators
```

External detection references commonly associate Mimikatz `sekurlsa::logonpasswords` behavior with Sysmon process access event ID `10` and Windows Security object access event ID `4663` when LSASS memory is accessed. These are useful inspection hints, not assumptions that must appear in this specific dataset.

## What to record during implementation

The real import branch should record:

```text
dataset page URL
download URL or repository path
download date
archive filename
archive file listing
raw file names inspected
raw record count
selected raw fields
number of extracted events
timestamp mapping
host mapping
event_type mapping
severity mapping
observed_state mapping
known limitations
```

## Commit policy

Do not commit large raw archives.

Preferred structure:

```text
data/raw/
    not committed, or documented only

data/processed/
    small extracted event table if license-compatible and appropriate

docs/data/
    inspection and extraction notes

tests/fixtures/
    tiny representative fixture for automated tests
```

## Success criterion

This inspection is successful when the next implementation branch can produce:

```text
real Empire Mimikatz LogonPasswords event material
    → documented extracted event table
    → successful load_mordor_event_csv call
    → normalized ASTRA telemetry DataFrame
```

without changing ASTRA's impairment, belief, metric, reporting, or visualization modules.

## Non-goals

This step does not attempt:

```text
general Mordor / OTRF ingestion
full raw JSON parser
multi-scenario benchmark
complete ATT&CK modeling
automatic compromise ground-truth reconstruction
SOC-grade alert semantics
```
