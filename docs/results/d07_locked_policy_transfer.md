# D07.2 — Locked-policy transfer to Comsvcs.dll MiniDump telemetry

## Status and scope

This note records the **implementation and experiment contract**. No real Comsvcs transfer outputs are asserted until the locally downloaded ZIP has been processed. The D07.1 design was predeclared and committed separately (`6be79dc`), and its structural preflight has been independently reproduced and committed (`9cde598`). D06's P1/P2/P3 encoders and common grouping implementation are imported unchanged.

The second case is OTRF `SDWIN-201018195009` — **LSASS Memory Dump via Comsvcs.dll**. It is still within the LSASS credential-access family, so this is a limited portability check, not broad security-domain validation.

## Source record findings already inspected

The user inspected the raw archive with a read-only script and reported 184 records; Event ID 10 includes two `rundll32.exe → lsass.exe` access records, Event ID 1 includes one `rundll32.exe comsvcs.dll MiniDump ...` process creation, and Event ID 7 includes one `comsvcs.dll` image load. The process-creation, load, and access records share PID `4824` and process GUID `{39e4a257-d4ad-5f8c-3303-000000000700}`. The two Event ID 10 records target LSASS PID `756`, also specified by the MiniDump command. These observations support linkage of recorded processes, not independent proof of successful credential extraction.

The three **predeclared** evidence questions are:

- **T1:** an Event ID 10 record with target image basename `lsass.exe`.
- **T2:** T1 and source image basename `rundll32.exe` in **the same record**.
- **T3:** an Event ID 1 record with image basename `rundll32.exe` and a **single command line** containing `comsvcs.dll` and `minidump`.

They are evidence indicators, not compromise state labels; T3 is **not** inferred from T2. Event ID 7 image load is supporting context but not a new primary claim.

## Source anchoring and timestamp handling

The executable validates the raw archive and JSON member against D07.1's committed SHA-256 values, preserves source position and per-line SHA-256 in a fixed source inventory, and never passes indicator labels to an encoder. The preflight records 148 source-UTC timestamped rows and 36 rows without a usable timestamp. **Only the 148 source-timed rows are eligible for UTC-aligned 5/10/30-second tumbling-window comparison.** The 36 untimed records remain in the full source inventory and full P0 raw output; no synthetic timestamp is invented. Therefore the count and byte ratios for P1/P2/P3 apply to 148 eligible rows, not the full 184. All identified T1/T2/T3 witnesses in the user diagnostic carry source UTC times; this is verified again by the runnable experiment.

## Locked representations and decoding

- **P0 raw:** preserves original records and source identity, with separate full-population and timed-subset JSONL outputs.
- **P1 count-only:** host/window/count. Missing structured evidence is **indeterminate**, not automatically false.
- **P2 joint fields:** original D06 process-access tuples `(EventID, SourceImage, TargetImage, multiplicity)` for Event ID 10 plus an event-type histogram for all event types.
- **P3 joint fields + source PID:** exactly the original D06 P3 tuple and time-range policy.

The D07 *query-only* decoder consumes serialized P1/P2/P3 bytes. It can support T1/T2 from joint Event ID 10 tuples. For T3, it returns `indeterminate` when the histogram contains an Event ID 1, because P2/P3 discard its image and command line; it returns `unsupported` when the histogram proves there is **no** Event ID 1. It never reconstructs process GUID relationships from discarded fields. P0 directly evaluates the relevant raw fields.

D07 uses a fixed raw-source reference for evaluation only. False support and false exclusion are evaluated per aggregate, separately from the claim ledger, which is merely the union of supported claims.

## Reported quantities

The script writes a fixed event inventory, JSONL representation outputs, a policy-summary CSV, a group/claim reconstruction CSV, and a manifest recording code/source/output checksums. It reports counts of source and eligible records, count reduction for eligible records, canonical JSONL and deterministic gzip bytes (proxies only), group-level support/indeterminacy/unsupported outcomes, false support/exclusion, earliest synthetic aggregate emission time and witness availability under 5/10/30/180-second buffering deadlines.

A known expected finding (from **schema**, before running the second source) is that P2/P3 cannot positively establish T3. That should be presented as a representation boundary, not as a newly discovered property of attacks. The transfer analysis seeks to quantify costs and behavior, not to prove that a generic process-access aggregate is an effective attack detector.

## Limitations and controls

1. The candidate is another LSASS credential-access operation; it is not independent SOC data or unrelated-attack generalization.
2. No practitioner study, calibrated belief, or improved SOC decision-making is measured.
3. Claim definitions are taken from the documented security operation and raw fields; successful recovery is conditional on the representation schema.
4. Unknown-time source records are excluded from window-based comparisons and always reported, rather than silently imputed.
5. The aggregate JSONL and compressed byte sizes are reproducible proxies; no measured resource cost is claimed.
6. Process-GUID correlation can be examined in P0 but **cannot** be recovered by P2/P3 because their locked schemas omit GUID and Event ID 1 command line.
7. Existing D03–D06 outputs and encoders are not modified.

## Reproduction

From repository root (with D07.1 report and original archive already present):

```bash
python scripts/run_d07_transfer_comparison.py
PYTHONPATH=src:. python -m pytest -q
```

Inspect `outputs/d07_transfer_comparison/d07_transfer_summary.csv` and `d07_transfer_manifest.json` before interpreting results. The patch for this stage deliberately does not include fabricated real-case outputs.
