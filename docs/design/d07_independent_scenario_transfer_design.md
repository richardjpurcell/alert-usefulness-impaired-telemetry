# D07.1 — Predeclared cross-scenario transfer test

**Status:** Design locked before inspecting the candidate's raw telemetry. No D07 results are claimed by this document.

**Revision branch at design time:** `dtrap-reproducibility-revision`, latest verified user commit `ae9dfe0` (D06 results). The D06 policy implementation is at commit `1aab65d`.

## Motivation and candidate

D03–D06 investigate the Mordor / OTRF **Empire Mimikatz LogonPasswords** scenario. The next question is whether the *same* fixed-reference, evidence-reconstruction and aggregation methodology is informative on a different documented operation, without changing an encoder to make it succeed.

**Second scenario (frozen candidate):** OTRF atomic dataset **Lsass Memory Dump via Comsvcs.dll**, identifier `SDWIN-201018195009`, documented 2020-10-18. The scenario describes `rundll32.exe` invoking `comsvcs.dll` `MiniDump` to dump LSASS memory. Source: <https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201018195009.html>.

**Official raw-data URL:** <https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip>.

This is transfer **within LSASS credential-access monitoring**, not across different ATT&CK tactics, organizations, or SOCs. The original scenario and new candidate must never be merged or treated as independent operational SOC observations.

## Ordered stages and freeze boundary

1. **Freeze this design** in a Git commit before inspecting the candidate's event composition or evidence outcomes.
2. Download the original candidate archive without repackaging it. Preserve download URL, original ZIP SHA-256, member name and decompressed member SHA-256. Run read-only structural preflight; do not derive attack truth from scenario title.
3. Establish an immutable raw reference for this scenario: event position, SHA-256 of original line, host, EventID, time and time basis. New event labels are derived independently from original raw fields and only used by the evaluator, *never* by encoders.
4. Apply **unchanged** D06 P0/P1/P2/P3 encoder definitions (exact field selection, host normalization, UTC-aligned 5/10/30 s windows, canonical JSONL). Any necessary generic adapter to ingest the new ZIP must be separately reported. Do not add a special `comsvcs.dll` field or detector to P2 or P3 during this primary test.
5. Decode the stored outputs using the predeclared queries below, comparing with the immutable raw reference; report identified/indeterminate/unsupported states, payload size and deadline delay. Only after the primary comparison may exploratory variants be considered, clearly marked **post hoc**.

## Evidence questions (not ground-truth compromise labels)

* **T1 — General LSASS access**: a raw Sysmon EventID 10 record whose `TargetImage` basename is `lsass.exe`.
* **T2 — Rundll32-to-LSASS access**: T1 and the *same record's* `SourceImage` basename is `rundll32.exe`.
* **T3 — Comsvcs MiniDump invocation**: a raw EventID 1 process-creation record with a `rundll32.exe` image and a single `CommandLine` containing both `comsvcs.dll` and `minidump` (case-insensitive). These conditions must be joined **within the same source record**, not pieced together from independent events. This is an observable invocation indicator, not proof of successful dumping.

The official adversary documentation establishes *scenario intention and procedure* separately. The raw trace establishes which T1/T2/T3 indicators were actually recorded; a missing T3 record does not refute the scenario and must not be counted as an unsuccessful attack.

These three claims are **not nested**: T3 does not imply that an EventID 10 was logged, and T2 does not prove T3.

## Fixed representations and expected information boundaries

* **P0 Raw:** complete original record fields and stable record identity; T1, T2, T3 can be evaluated where the raw source provides the requisite fields.
* **P1 Count-only:** host/window/count; T1/T2/T3 generally indeterminate, never unsupported solely because relevant fields are absent.
* **P2 Joint process fields:** EventID histogram and `(EventID, SourceImage, TargetImage, multiplicity)` for **all** EventID 10 records; can evaluate T1/T2 when fields are complete, but cannot establish T3 because EventID 1 command line is absent.
* **P3 Joint fields + PID:** same as P2 plus source PID and source timestamp range; T1/T2 can be evaluated; **T3 remains indeterminate** because EventID 1 command line is absent. It would be invalid to infer T3 merely from `rundll32.exe -> lsass.exe` or a PID.

T1/T2 are configured as **evaluation queries**, not encoder filters. The D06 encoder `encode_group` and JSON schemas remain locked. A generic query-only decoder may be added, but results must be marked D07 reconstruction rather than silently replacing the D06 decoder. Any changes to encoder logic mean the primary transfer test has failed to use an unchanged encoding; report that failure before a separate redesign.

## Primary measures

1. Preflight: archive/member SHA-256, total source records, EventID histogram, hosts, timestamp basis, completeness of EventID 10 source/target images and EventID 1 image/command line.
2. For each P0–P3 and each aggregation window: unit count, canonical serialized bytes and deterministic gzip bytes; these are proxies for representation cost, **not** measured runtime, storage or SOC cost.
3. T1/T2/T3 source indicator counts (evaluation-only) and policy reconstruction outcomes (`supported`, `unsupported`, `indeterminate`). Compare only matching host/time windows; distinguish aggregate-level support from exact source-event identity.
4. False support and false exclusion, relative to the raw-source indicators. Missing data and unsupported queries must not be coded as negative evidence.
5. Claim ledger acquisition and earliest emission time from retained evidence; deadline checks at 5, 10, 30, 180 s with buffering delay explicitly described as synthetic. Report index-time fallback separately.
6. Exact unchanged-policy check: encoder source hash / Git revision, output determinism, and regression tests for D03–D06.

## Success, failure and inconclusive outcomes

**Method transfer passes** if the new raw archive is parsed and anchored immutably; P0–P3 run without altering the declared encoding policies; reconstruction does not invent evidence from cross-event joins; and omissions are reported as indeterminate. It need **not** recover T3 under P2 or P3. Success means *audit mechanism portability*, not validated detection accuracy.

**Method transfer fails** if encoding schemas must change to process the scenario, evaluation labels leak into encoding, or a decoder fabricates / falsely excludes evidence relative to the frozen source reference. These failures remain reportable results; no post hoc change to the primary comparison is allowed.

**Evidence-coverage inconclusive** if T1/T2/T3 source evidence is absent or too sparse to estimate the intended preservation trade-off; the lack of records is reported and the candidate is not silently replaced. The candidate should not be counted as an independent success for T1/T2/T3 in that case.

**Broader novelty gate:** One additional attack within the same technique family is a *limited* robustness check. Regardless of outcome, do not claim operational SOC utility, general detector improvement, calibrated probabilities or broad generalization. Decide after D07 whether the submission needs a genuinely different task or security-event family.

## Structural preflight and repository hygiene

The preflight script `scripts/run_d07_scenario_preflight.py` uses only Python's standard library, reads the original ZIP without extracting or changing it, verifies JSONL record shape, counts selected field availability, and emits a reproducible machine-readable report. It **does not** classify attacks or run P0–P3. Do not commit the raw archive until source-data licensing and distribution terms have been verified. Commit the design first; stage the preflight implementation and generated report separately after running on the source.

## Required tests

* Detect corrupt ZIP / invalid JSON / ambiguous JSON members rather than silently choosing a convenient input.
* Stable line count, ZIP/member hash and deterministic repeated output.
* Distinguish `UtcTime` from `@timestamp` fallback and unknown timestamps.
* Handle absent and string-valued EventID and missing field values.
* No scenario-specific evidence detection or D03 source labels in preflight.
* Primary D07 decoder must use only encoded bytes and declared queries; synthetic `{rundll32->other.exe, svchost->lsass.exe}` must NOT support T2.
* P2/P3 can never assert T3 on the basis of EventID 10 fields alone.
* Existing D03–D06 tests and committed output checksums unchanged.
