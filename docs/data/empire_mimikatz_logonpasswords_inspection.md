# Empire Mimikatz LogonPasswords inspection note

This note records the initial inspection of ASTRA's first real Mordor / OTRF scenario import.

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

## Download and local raw-data location

The selected scenario archive was downloaded into the local raw-data working area:

```text
data/raw/mordor/empire_mimikatz_logonpasswords.zip
```

This raw archive is not intended to be committed.

Download command used:

```bash
curl -L -O https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip
```

## Archive inspection

Initial archive inspection showed:

```text
archive filename: empire_mimikatz_logonpasswords.zip
archive size: approximately 700 KB
archive contents: empire_mimikatz_logonpasswords_2020-08-07103224.json
extracted file size: 43,478,765 bytes
record count: 6,026 lines
format: JSON Lines / NDJSON
```

The file is not a single JSON document. It contains one JSON object per line.

Attempting to load the file as a single JSON object produced:

```text
json.decoder.JSONDecodeError: Extra data: line 2 column 1
```

This confirmed that the file should be parsed line by line.

## Raw file

Extracted file:

```text
data/raw/mordor/empire_mimikatz_logonpasswords/empire_mimikatz_logonpasswords_2020-08-07103224.json
```

The raw extracted file is large enough that it should remain outside version control unless a later decision is made to commit a small processed derivative.

## First-record inspection

The first inspected records contain Sysmon process-access events. The first inspected record included:

```text
Channel: Microsoft-Windows-Sysmon/Operational
SourceName: Microsoft-Windows-Sysmon
EventID: 10
Hostname: MORDORDC.theshire.local
@timestamp: 2020-08-07T14:32:25.358Z
EventTime: 2020-08-07 10:32:22
UtcTime: 2020-08-07 14:32:22.692
Severity: INFO
SeverityValue: 2
SourceImage: C:\windows\system32\svchost.exe
TargetImage: C:\windows\System32\svchost.exe
GrantedAccess: 0x1000
```

Initial fields observed in the first record included:

```text
tags
TargetProcessGUID
@version
EventType
Version
ThreadID
EventTime
Task
AccountType
SourceProcessGUID
CallTrace
Channel
SourceName
OpcodeValue
Hostname
@timestamp
Message
SourceModuleName
ProcessId
SourceImage
EventReceivedTime
port
AccountName
UtcTime
GrantedAccess
Domain
ExecutionProcessID
host
SourceProcessId
SourceThreadId
Severity
TargetProcessId
SeverityValue
EventID
UserID
ProviderGuid
RecordNumber
SourceModuleType
Keywords
TargetImage
RuleName
```

## Confirmed candidate field mapping

Candidate field mapping for the first extracted ASTRA table:

```text
timestamp      ← @timestamp or UtcTime
host           ← Hostname
event_type     ← EventID, possibly combined with Channel or SourceName
severity       ← Severity or mapped SeverityValue
observed_state ← derived from EventID, image fields, command-line fields, Message, and scenario-specific indicators
```

The raw field `host` is also present, but in the first inspected records it refers to the log collection host:

```text
wec.internal.cloudapp.net
```

For ASTRA's host-level belief state, `Hostname` is the better candidate for `host`.

## Actual field and indicator inspection

Additional inspection confirmed that the extracted scenario file is JSON Lines / NDJSON with one event record per line.

Record count:

```text
6,026 records
```

Observed host distribution:

```text
WORKSTATION5.theshire.local    5,188
MORDORDC.theshire.local          528
WORKSTATION6.theshire.local      310
```

Observed channel distribution:

```text
Windows PowerShell                          2,949
Microsoft-Windows-PowerShell/Operational    1,695
Security                                      702
Microsoft-Windows-Sysmon/Operational          679
Microsoft-Windows-WMI-Activity/Operational      1
```

Observed source distribution:

```text
PowerShell                              2,949
Microsoft-Windows-PowerShell            1,695
Microsoft-Windows-Security-Auditing       702
Microsoft-Windows-Sysmon                   679
Microsoft-Windows-WMI-Activity               1
```

Most common observed EventIDs:

```text
800     2,940
4103    1,695
10        272
5156      211
5158      195
12        154
3          90
4658       86
7          81
4656       49
13         45
4690       43
4663       43
11         14
4703       13
5          11
4689       11
4672       10
4624       10
4627       10
```

The dataset is heavily PowerShell-oriented, with additional Security and Sysmon records. Sysmon EventID 10 process-access records are present, which is relevant to the LSASS-memory access scenario.

## TargetImage and SourceImage inspection

Most common `TargetImage` values:

```text
None                                                        5,754
C:\windows\System32\svchost.exe                              126
C:\windows\system32\svchost.exe                               83
C:\Windows\System32\RuntimeBroker.exe                          5
C:\windows\system32\lsass.exe                                  4
C:\windows\system32\whoami.exe                                 3
C:\ProgramData\Microsoft\Windows Defender\...\NisSrv.exe        3
C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe       3
C:\windows\system32\csrss.exe                                  3
C:\windows\system32\fontdrvhost.exe                            3
C:\windows\system32\DllHost.exe                                3
```

Most common `SourceImage` values:

```text
None                                                        5,754
C:\windows\system32\svchost.exe                              262
C:\windows\system32\lsass.exe                                  3
C:\ProgramData\Microsoft\Windows Defender\...\MsMpEng.exe       3
C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe       2
C:\windows\system32\csrss.exe                                  1
C:\windows\system32\conhost.exe                                1
```

Most records do not contain `SourceImage` or `TargetImage`, but the image fields are available for some Sysmon records and should be used when present.

## Simple indicator search

Simple string matching over the raw records produced:

```text
mimikatz           0
sekurlsa           0
logonpasswords     0
lsass.exe        230
powershell      4,833
```

The absence of literal `mimikatz`, `sekurlsa`, and `logonpasswords` strings means the first extraction should not rely on explicit tool-name matching. Instead, the extraction should use event semantics, including PowerShell activity, LSASS references, Sysmon process-access events, and relevant Windows Security events.

## Example indicator records

The first matching records were mostly PowerShell-related. Examples included:

```text
EventID 12
Host: WORKSTATION5.theshire.local
Message: Registry object added or deleted
Image: C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

```text
EventID 5158
Host: WORKSTATION5.theshire.local
Message: Windows Filtering Platform permitted a bind to a local port
Application: powershell.exe
```

```text
EventID 5156
Host: WORKSTATION5.theshire.local
Message: Windows Filtering Platform permitted a connection
Application: powershell.exe
```

```text
EventID 3
Host: WORKSTATION5.theshire.local
Message: Network connection detected
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

```text
EventID 800
Host: WORKSTATION5.theshire.local
Message: PowerShell pipeline execution details
```

These examples suggest that the first extraction should preserve both PowerShell-heavy activity and LSASS-related records rather than filtering too aggressively.

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

For this scenario:

```text
source_dataset = mordor
scenario = empire_mimikatz_logonpasswords
```

## Preferred field mapping

For the first extracted table, the preferred mappings are:

```text
timestamp      ← @timestamp
host           ← Hostname
event_type     ← derived from EventID and Channel
severity       ← derived from EventID, Channel, Message, and scenario-specific rule
observed_state ← derived from EventID, Message, TargetImage, SourceImage, and scenario-specific rule
```

`@timestamp` is preferred because it is ISO-like and consistently present in inspected records.

`Hostname` is preferred over `host` because it identifies the scenario host rather than the collection host.

`event_type` should be compact and ASTRA-facing. It does not need to preserve every raw Windows event detail.

## Initial event-type mapping candidate

A first event-type mapping could use compact labels such as:

```text
powershell_pipeline
powershell_module
sysmon_process_access
sysmon_network_connection
security_object_access
security_handle_event
security_logon
registry_change
file_create
image_load
other_security_event
other_event
```

Candidate raw mapping:

```text
EventID 800      → powershell_pipeline
EventID 4103     → powershell_module
EventID 10       → sysmon_process_access
EventID 3        → sysmon_network_connection
EventID 4663     → security_object_access
EventID 4656     → security_handle_request
EventID 4658     → security_handle_closed
EventID 4624     → security_logon
EventID 12 or 13 → registry_change
EventID 11       → file_create
EventID 7        → image_load
```

This should be implemented as a first-pass extraction rule, not as a universal Windows event taxonomy.

## Initial observed_state mapping candidate

Use ASTRA's simple state observation vocabulary:

```text
benign
suspicious
compromised
```

A first conservative extraction rule could classify records as follows:

```text
compromised
    Events with LSASS references, especially process-access activity involving
    lsass.exe or EventID 10 with credential-access relevance.

suspicious
    PowerShell-heavy activity, process creation, network activity, registry
    changes, or security events that occur in the scenario window and plausibly
    support the credential-access chain.

benign
    Background events that are not directly tied to PowerShell execution,
    LSASS access, credential access, or supporting attack activity.
```

A more concrete first-pass rule could be:

```text
compromised
    Message, SourceImage, or TargetImage contains lsass.exe.

suspicious
    Channel or SourceName indicates PowerShell;
    EventID is one of 800, 4103, 10, 3, 12, 13, 4656, 4658, 4663, 4690;
    or Message contains powershell.

benign
    Remaining events retained as context.
```

This is an ASTRA abstraction for the experiment. It is not universal security ground truth.

## Initial severity mapping candidate

Use ASTRA's simple categorical scale:

```text
low
medium
high
```

Proposed initial mapping:

```text
high
    observed_state is compromised;
    or record contains lsass.exe;
    or EventID 10 involves LSASS-related process access.

medium
    observed_state is suspicious;
    PowerShell activity;
    security-object access;
    registry activity;
    network activity in the scenario window.

low
    remaining background/context events.
```

If the raw `Severity` and `SeverityValue` fields are useful, they can be preserved or incorporated, but in the inspected first records `Severity` is often `INFO`, which is not by itself sufficient for ASTRA's scenario-level usefulness abstraction.

## Expected implementation approach

The next implementation branch should parse the NDJSON line by line and produce a small extracted CSV.

Suggested implementation target:

```text
scripts/extract_mordor_empire_mimikatz.py
```

Possible output path:

```text
data/processed/empire_mimikatz_logonpasswords_events.csv
```

However, the processed file should only be committed if it is small, license-compatible, and appropriate for the repository. Otherwise, commit only a small fixture and documentation.

The extraction script should:

```text
read raw NDJSON line by line
select or retain relevant records
derive timestamp from @timestamp
derive host from Hostname
derive event_type from EventID and Channel
derive severity from scenario-specific rule
derive observed_state from scenario-specific rule
write Mordor-like event CSV
validate that load_mordor_event_csv can load the output
```

## Commit policy

Do not commit large raw archives.

Preferred structure:

```text
data/raw/
    not committed, or documented only

data/processed/
    small extracted event table only if license-compatible and appropriate

docs/data/
    inspection and extraction notes

tests/fixtures/
    tiny representative fixture for automated tests
```

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
