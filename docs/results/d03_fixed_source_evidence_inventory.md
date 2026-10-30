# D03 — Fixed source-evidence inventory (Mordor Empire Mimikatz)

**Status:** Reproducible, read-only baseline; this is an evidence-provenance experiment, **not** a ground-truth host-compromise or alert-usefulness experiment.

## Research question

Can we establish a fixed, traceable source-event reference **before** replay impairment or aggregation, so that later comparisons measure whether relevant evidence is preserved rather than silently changing the reference state?

## External scenario context versus trace evidence

The [OTRF Empire Mimikatz LogonPasswords scenario](https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-190518202151.html) documents execution of the Empire `credentials/mimikatz/logonpasswords` module from an agent on `WORKSTATION5`, PID `1648`. This scenario documentation supports the *association parameters*, not a second-by-second host-compromise label. Observing an LSASS process access is not proof of successful credential extraction or SOC analyst knowledge.

D03 reads the original, unmodified JSON Lines member from `data/raw/mordor/empire_mimikatz_logonpasswords.zip`. This script **does not use** the existing processed `observed_state` or severity labels and does not alter any existing experiment or code.

## Indicator definitions (nested, not interchangeable)

| Indicator | Deterministic structured-field rule | Interpretation |
| --- | --- | --- |
| `lsass_access` | Sysmon `EventID == 10` and Windows basename of `TargetImage == lsass.exe` | Observed process-access telemetry targeting LSASS; potentially benign or suspicious |
| `powershell_lsass_access` | Prior condition and basename of `SourceImage == powershell.exe` | Narrower process-to-LSASS evidence |
| `documented_agent_lsass_access` | Prior condition and short `Hostname == WORKSTATION5` and `SourceProcessId == 1648` | Event matching the documented execution agent identifiers, not independently established compromise |

We deliberately **do not** match free-text mentions of `lsass.exe` in `Message` or treat the `compromised` label from the original extractor as ground truth. All paths are compared case-insensitively by Windows basename. The `WORKSTATION5`/`1648` correspondence is declared explicitly, and may be changed with CLI arguments for diagnostic purposes.

## Verified results (bundled raw archive)

| Quantity | Result |
| --- | ---: |
| Source events / inventory rows | 6,026 |
| Distinct hosts | 3 |
| Structured EventID 10 LSASS-target accesses | 4 |
| PowerShell-to-LSASS accesses | 1 |
| Match to documented agent's host/PID | 1 |

Evidence rows (source line refers to the **original ZIP member NDJSON line number**, one-based):

| Source line | UTC source time | Source process | PID | GrantedAccess | Indicator class |
| ---: | --- | --- | ---: | --- | --- |
| 818 | 2020-08-07 14:32:46.927 | `svchost.exe` | 452 | `0x1000` | LSASS process access |
| 822 | 2020-08-07 14:32:46.927 | `svchost.exe` | 452 | `0x1000` | LSASS process access |
| 2451 | 2020-08-07 14:32:56.540 | `powershell.exe` | 1648 | `0x1010` | Documented-agent match |
| 4206 | 2020-08-07 14:33:44.832 | `svchost.exe` | 1784 | `0x2000` | LSASS process access |

All four are on `WORKSTATION5.theshire.local`. The apparently duplicate line 818/822 is **not silently deduplicated**: each archive line has a distinct source-event ID and content hash, permitting a future duplication/identity analysis.

## Provenance and timestamps

The inventory retains, for **every** original source record, its one-based line number, a stable line-based ID, the SHA-256 of the original NDJSON line bytes (excluding line ending), host, EventID, RecordNumber, event-time basis, and index timestamp.

For `event_time_utc`, the script selects `UtcTime` where supplied and parseable (explicitly source-side UTC); otherwise it uses `@timestamp`, **labelled** `index_timestamp_fallback`. Do **not** treat the fallback as independent event-generation time. `EventReceivedTime`/`EventTime` may lack an explicit timezone and are not used to calculate transport delay. Later delays should be controlled synthetic interventions against declared reference timing, with the fallback distinction retained.

The manifest records the source archive SHA-256, the uncompressed member SHA-256, selected host and PID, indicator rules, counts, output paths and output-file SHA-256. The original archive is unmodified. Later experiments should reject references with mismatched archive/member hashes and should keep the inventory fixed across impairments and aggregation.

## Reproduce

From the repository root, with the raw ZIP present:

```bash
python3 scripts/build_d03_source_evidence_inventory.py
PYTHONPATH=src:. python3 -m pytest -q tests/test_d03_source_evidence_inventory.py
```

For the entire repository test suite (this uses the repository's `src` package layout):

```bash
PYTHONPATH=src:. python3 -m pytest -q
```

Outputs:

- `outputs/d03_source_evidence/d03_source_event_inventory.csv` — full inventory, **6,026** rows with minimal metadata and evidence flags.
- `outputs/d03_source_evidence/d03_lsass_access_evidence.csv` — the four evidence records with process fields.
- `outputs/d03_source_evidence/d03_evidence_manifest.json` — checksums, selection rules, and caveats.

## Limits and next controlled test

This is a *source-evidence inventory* rather than a calibrated detection system. Its narrow evidence predicates are defined in advance; finding an event that satisfies those predicates is a tautological rule match, not independent confirmation of compromise. The external scenario transcript documents the attack context, but does not provide full per-event labels or analyst decisions.

**Next, D04** should use these fixed identities to compare lost/delayed/aggregated streams against the same reference, distinguishing (i) source-record representation, (ii) availability of a specific process-to-LSASS indicator by an explicit deadline, and (iii) preservation of fields needed to recognize it. Do not reconstruct the reference state from each impaired or aggregated stream. A later belief audit would require a separately justified state target and update rule.
