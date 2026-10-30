# JISA revision — Claim–evidence matrix and manuscript blueprint (v0.1)

**Status:** Working scientific-argument plan; not manuscript text and not a claim that JISA submission requirements have been satisfied.  
**Research branch:** `dtrap-reproducibility-revision`, user-verified at `d29e93c` (D07 transfer results), clean and pushed.  
**Inputs inspected:** The ten uploaded original ACM LaTeX sections (`0_abstract` through `9_conclusion`), original manuscript PDF, D03–D07 research notes, and the reported local reproductions (168 tests after D07).  
**Proposed destination:** *Journal of Information Security and Applications* (JISA); confirm journal-specific author requirements when setting up the submission files.

## 1. Scientific decision and new paper identity

The original manuscript evaluates whether incoming telemetry improves a scalar host-compromise estimate. Its positive, clipped update rule and telemetry-derived reference target yielded high healthy baseline error (0.9419) and misleading usefulness labels; those results cannot be offered as evidence of correctly measured security-state usefulness. In addition, its flood outcome was guaranteed by zero-weight synthetic flood events, and its original aggregation experiment recomputed the target from aggregated evidence.

The revised paper should instead be a **bounded evidence-preservation and maintained-evidence-state audit methodology**, asking:

> Under declared telemetry impairments and representations, which security-evidence claims can a monitoring system support, which become indeterminate, and how do these changes affect a maintained evidence state and measurable representation costs?

This is **not** a validated host-compromise estimator, detection/prioritization algorithm, deployed SOC performance evaluation, or universal metric of intrinsic alert usefulness.

### Working title options

1. **Auditing Evidence Preservation Under Impaired Security Telemetry** (preferred; makes the demonstrated object clear)
2. **From Telemetry Delivery to Maintained Evidence: A Reproducible Security-Monitoring Audit**
3. **What Security Telemetry Preserves: Auditing Impairment and Aggregation Across Adversary-Emulation Traces**

**Scope correction:** We have two documented *scenarios*, not two independent operational SOC datasets. Both concern LSASS credential access, so D07 is *within-domain transfer*, not broad generalization.

## 2. Claim–evidence matrix

Legend: **Supported** = present experiments directly support bounded statement; **Conditional** = supported only under carefully stated scope; **Not established** = do not claim.

| ID | Candidate statement for revised paper | Evidence and exact comparison | Assessment | Acceptable wording / boundary |
| --- | --- | --- | --- | --- |
| C1 | A fixed-source reference can be maintained across loss, delay and aggregation, avoiding moving-target evaluation. | D03 fixed inventory of 6,026 records; four structured LSASS accesses and one documented-agent association; D04 checks D03 hashes and measures loss/delay against fixed evidence IDs. | **Supported, methodological** | A reproducible experimental contract; not independent host-compromise truth. |
| C2 | Physical retention, identifiability, and deadline-qualified availability are distinct audit quantities. | D04: at 240/600-second synthetic delays, 40/40 LSASS evidence-record observations remain represented over ten seeds but 32/40 meet the 180-second deadline; scenario-agent match meets it in 7/10 runs. | **Supported, constructed intervention** | Report declared per-event synthetic delay and fixed denominators; not real network latency. |
| C3 | A maintained evidence ledger distinguishes acquisition of new claims from repeated evidence and from telemetry irrelevant to the chosen claims. | D05 healthy replay: 2 events add claim(s), 2 repeat existing claims, 6,022 add no claim among A/B/C; longer delay conditions keep 10/10 complete C claims but only 7/10 by the synthetic deadline. | **Supported, narrowly** | These are outcomes *of a declared three-claim ledger*; 6,022 records are not therefore operationally useless. D05 reads declared D03 annotations, not independent detection. |
| C4 | Different serialized aggregation representations retain different evidence distinctions at measurable payload costs. | D06 at 5 s: P0 6,026 raw units / 744,090 gzip bytes; P1 90 / 762; P2 90 / 1,983; P3 90 / 2,848. P2 supports A and B, P3 supports C as well. | **Supported, representation-dependent** | PID/timestamp-range retention costs 865 additional gzip bytes versus P2 for that setting; recovery of C largely follows from retaining its defining field. Bytes are *serialization proxies*, not measured SOC cost. |
| C5 | The locked representation comparison transfers to another documented execution mechanism and exposes a missing distinction. | D07 Comsvcs.dll MiniDump: 184 raw records, 148 UTC-timed eligible for windows, 36 untimed. Two rundll32-to-LSASS EventID 10 records; one MiniDump command line; one Comsvcs image load, all sharing the same process GUID. P2/P3 support T1 and T2; neither supports T3. | **Supported, conditional** | Transfer is within LSASS credential-access scenarios. The failure of T3 follows from excluded EventID 1 command-line fields; it is a useful disclosed representational limit, not a surprising detector failure. |
| C6 | More retained fields are not necessarily more informative for a particular declared query. | D07 at 5 s: P2 405 gzip bytes, P3 501 (+96), both support T1/T2 and fail to reconstruct T3. D06 differs because P3 supports agent PID association C. | **Supported, query-dependent** | Avoid universal P2/P3 ranking; value depends on the question and preserved fields. |
| C7 | The method measures alert usefulness / improves compromise estimates, alert priority, or analyst decisions. | No independent state target, analyst outcomes, production SOC measurements, or comparative decision task; original model diagnosed as invalid for these claims. | **Not established** | Explicitly exclude. Do not infer operational gains from event count or gzip byte reduction. |
| C8 | The method is novel relative to aggregation, event correlation, and provenance systems. | Current experiments expose a transparent audit decomposition; relevant existing work already retains security context and reduces alerts (e.g., Landauer et al., NoDoze, HOLMES). | **Not yet established as a strong comparative claim** | Claim a *specific measurement and audit contract* and contrast precisely with prior purposes; need related-work analysis and a bounded validation decision before calling it superior. |

**Different denominators:** D06 operates on all 6,026 D03 records but mixes 679 verified Sysmon `UtcTime` values with 5,347 labelled index-timestamp fallbacks. D07 timed aggregation operates on only 148 of its 184 raw records. Never compare raw/aggregate byte ratios as if those populations were identical across studies; never equate aggregate supported-group counts with raw matching-event counts.

## 3. Proposed contributions (maximum three)

**Contribution 1 — Fixed-reference audit semantics.** A reproducible audit contract that separates source evidence, delivery/representation, identifiable or timely evidence, and changes in an explicitly declared evidence-state ledger. Distinguish supported, unsupported and indeterminate claims; do not conflate evidence absence with missing fields.

**Contribution 2 — Controlled comparison of telemetry representations.** Measurements of recoverable structured evidence claims, claim ambiguity, source-event identity availability, synthetic buffering delay and canonical/gzip serialization size under locked field-retention policies. Comparative claims are restricted to evaluated policies and scenarios.

**Contribution 3 — Bounded transfer and failure analysis.** Evidence from two documented LSASS-related adversary-emulation scenarios: field-based recovery transfers for process-access queries, while an unretained command line prevents reconstruction of a MiniDump invocation. Show both success and limitation without retuning P2/P3 after examining the second scenario.

**Do not put the old** “delivery and usefulness diverge” **observation first**. It is motivation/background and can be illustrated as a sanity check, not positioned as a new discovery.

## 4. Disposition of the original ACM LaTeX sections

| Old file | Decision | Specific instructions |
| --- | --- | --- |
| `0_abstract(5).tex` | **Replace** | Keep a one-sentence motivation; remove the three usefulness labels as headline outcomes, scalar error, saturation and flood dose-response as headline findings. Write after Results stabilize. |
| `1_introduction(7).tex` | **Rebuild with selective reuse** | Retain distinction between delivery and audit contribution and the boundary from analyst cognition. Replace original hypothesis and all four contributions with the three above; introduce evidence recoverability/indeterminacy and representation trade-off. |
| `2_related_work(5).tex` | **Retain backbone; strengthen** | Keep SOC monitoring, IDS metrics, threat-informed detection, controlled evaluation, and datasets. Deepen comparisons with aggregation, provenance/causal-correlation and evidence sufficiency. No false novelty claim that provenance-aware representations are new. |
| `3_problem_framing(5).tex` | **Substantial rewrite** | Retain `source event` and `audit unit`; replace latent compromise `X_t` with declared claim universe and maintained evidence state `K_t`. Add fixed oracle, evidence availability, identifiable claims, support/unsupported/indeterminate, and timing semantics. |
| `4_audit_model(5).tex` | **Replace main model** | Remove scalar `p_t`, additive clipped update, entropy-based usefulness classification, probability thresholds, `useful/redundant/misleading` and saturated flag from main method. Introduce the D05 monotone claim-set ledger and D06 decoder contract. If desired, discuss old model as a caution in appendix, not current evaluation. |
| `5_experiment_design(7).tex` | **Reconstruct around D03–D07** | Keep reproducibility discipline, seeded interventions, source provenance, and separation of controlled experiments. Specify both scenarios, fixed reference, D04 loss/delay, D05 replay, P0–P3 field representations, fixed windows, byte calculation, timestamp eligibility and locked-policy transfer. Delete weight sensitivity and original aggregated compromise target. |
| `6_results(5).tex` | **Replace** | Retire 34 useful / 5,959 redundant / 33 misleading, 0.9419 error, saturation fractions, flood as strongest finding, and original aggregation usefulness scores. Use the D04–D07 comparisons with exact denominators and limitations. |
| `7_threats_to_validity(4).tex` | **Retain useful discipline; rewrite substance** | Keep internal/external/construct/statistical taxonomy. Add claim-definition circularity, sparse positives, shared technique family, controlled emission/delay, index time fallbacks, untimed exclusions, synthetic policies, compression proxy vs operational cost, no real analyst validation, and absence of independent negative cases. |
| `8_ethics(4).tex` | **Adapt** | Keep defensive intent, public data, privacy, safe handling, no automated suppression from audit labels, AI use accountability if maintained. Ensure declarations align with journal requirements. |
| `9_conclusion(4).tex` | **Replace** | Reiterate only bounded findings: fixed-reference audit, representation/claim trade-off, transfer plus missing command-line evidence. No generic SOC improvement or universal usefulness claims. |

**Additional bibliography/figure assets:** The uploaded section files are sufficient to plan the rewrite, but not to compile a journal manuscript; we will later need the driver `.tex`, bibliography `.bib`, figure sources and style/package dependencies. Citation keys visible in old files are placeholders for reuse, not newly verified references.

## 5. Detailed new paper outline (proposed)

### 1. Introduction

- Problem: security-monitoring pipelines can preserve volume yet lose query-critical attributes, identity, or timeliness.
- Gap: detector performance, coverage and throughput do not themselves report whether a *declared evidentiary question* remains answerable after representation changes.
- Research questions: (RQ1) what is preserved? (RQ2) what enters maintained evidence state? (RQ3) what does retention cost? (RQ4) which conclusions transfer without policy retuning?
- Three constrained contributions above; explicitly exclude SOC outcome validation.

### 2. Prior Work and Positioning

- Alert overload, aggregation, triage (Landauer et al., Ghadermazi et al. from old paper).
- Security provenance/correlation and investigation (review NoDoze, HOLMES and closely related representation/evaluation work).
- IDS detection/coverage versus evidence recoverability; public adversary-emulation evaluation (original literature backbone).
- An explicit comparison table: prior primary objective, output, evaluation target, and what the current audit does *not* attempt.

### 3. Fixed-Reference Evidence Audit

- Source record/identity; declared indicator and scenario context; source reference vs experiment-side annotations.
- Evidence claim predicates, structured event relations, and nested claims; distinguish observational records from incident truth.
- Delivered/physically represented/identifiably available/by-deadline evidence.
- Decoder outcomes **supported / unsupported / indeterminate**, and what completeness is needed to justify a negative.
- Maintained ledger `K_{t+1} = K_t \cup C(e_t)` where `C(e_t)` is the supported-claim set under a declared representation; `new`, `repeat`, and `no claim` are ledger update outcomes, *not* calibrated usefulness labels.
- Scope boundary: no claim of correct host compromise or decision utility.

### 4. Datasets, Interventions, and Representation Policies

- Two OTRF scenarios and external scenario descriptions; raw counts and specific witness rules.
- D03 fixed inventory and archive/source checksums; D04 seeded loss/delay with declared synthetic latency.
- D05 unaggregated ledger; why it does not independently infer evidence from raw records.
- D06 P0 raw, P1 count, P2 joint process attributes, P3 joint plus PID; no evidence labels in encoders; locked 5/10/30 s buckets.
- D07 predeclared transfer to Comsvcs; process GUID evidence relationship; 148/184 source-timed eligibility.
- Evaluation measures: per-claim recoverability, ambiguity, error/overclaim, evidence identity, claim timing, bytes and count reduction.

### 5. Results I — Evidence Availability and Maintained State

- D04 loss/delay tables with *fixed denominators* and clearly synthetic deadlines.
- D05 healthy/impairment ledger outcome table; show that completed and by-deadline claim sets can differ.
- Interpret as controlled accounting, not alert rank or SOC detection benefit.

### 6. Results II — Representation Trade-offs

- D06 P0–P3 unit counts, gzip/JSONL size, A/B/C support; differentiate supported groups from witness events.
- Window buffering/deadline sensitivity; timestamp basis stratification.
- Explicitly state that retaining the defining field makes recovery possible *by construction*.

### 7. Results III — Locked-Policy Transfer

- D07 process identity and evidence witnesses; all four linked by process GUID; T3 invocation not recoverable from P2/P3.
- D07 5-second comparison (P0 148 timed raw, 14,783 gzip bytes; P1 4 groups/148 bytes; P2 4/405; P3 4/501); include 10/30-second conditions compactly.
- Contrast outcomes, especially P3's additional cost without any improvement for declared D07 claims. Explicit within-domain transfer only.

### 8. Discussion and Threats to Validity

- What the audit enables (inspection of why a query becomes indeterminate), and what it does not (better detection, improved priorities or decisions).
- Model choice, query choice, sparse evidence, constructed intervention effects, one family of attacks, timing exclusions, serialization proxies, no external SOC or analyst study.
- One bounded outstanding validation decision (below).

### 9. Conclusion

- A short, evidence-calibrated statement of fixed-reference auditing and its demonstrated policy dependence, with failure cases and future operational validation.

## 6. Exhibits: keep, replace, or build

| Exhibit | Origin/status | Recommendation |
| --- | --- | --- |
| Original Fig. 1 delivery vs represented | Old scalar-era figure | **Supplement or retire**; basic metric distinction can be narrated or used as a control, not main novelty. |
| Original Fig. 2 raw vs aggregated usefulness | Depends on invalid scalar outcomes | **Retire**. |
| Original Tables 5–8 (usefulness/error/saturation/weights) | Original model | **Retire from main paper**; optionally mention diagnosis as motivation/appendix. |
| **Figure A: audit architecture** | Proposed, not yet produced | Source record → impairment → retained representation → decoder → maintained claim set, with separate evaluation oracle. This should be the conceptual anchor. |
| **Table A: evidence sources and query semantics** | From D03/D07 | Two scenarios, observation types, external scenario context, claim definitions and scope. |
| **Figure/Table B: impairment vs ledger** | D04–D05 existing CSVs | Source retention vs identifiable/timely evidence; label synthetic deadlines and denominators. |
| **Figure/Table C: policy Pareto-style comparison** | D06/D07 existing CSVs | Plot gzip bytes against supported claim types, group counts/time as companion; no cost extrapolation. |
| **Table D: transfer predictions vs observations** | D07 design/results | T1/T2/T3 by P0–P3, plus explicit reason T3 is indeterminate. |
| **Table E: validity threats / evidence levels** | Proposed | Can be compact discussion table if page budget permits. |

## 7. Remaining validation gate — do not silently treat as completed

Before calling the revised paper sufficiently distinctive for JISA, resolve **one bounded validation choice**:

- Evaluate at least one independently motivated **negative or ambiguous control** (e.g., a scenario without the declared association, or matched process names that lack process identity), using policies frozen before inspecting the control; report `unsupported` vs `indeterminate` vs false support. Existing synthetic join-safety tests are necessary implementation guards, **not** an independent corpus-level specificity study.
- Alternatively, if this cannot be sourced or justified without launching a larger project, limit the paper to a *methods-and-controlled-demonstration* claim and accept increased editorial risk. Do not insinuate the gap is solved.

This is a **decision gate, not authorization to launch D08**. First draft the paper's claim/evidence boundaries and inspect whether a minimal independently documented negative case is available without changing method definitions.

## 8. Author workflow and version control

1. **Approve/revise this claim–evidence plan**; keep it as a design artifact, not as a paper section.
2. Commit it to `docs/design/jisa_claim_evidence_outline.md` on `dtrap-reproducibility-revision` with a clean working tree, after review.
3. Create a separate `manuscript/jisa/` working directory only once the argument is accepted; preserve original ACM source intact.
4. Gather main driver `.tex`, `.bib`, and figures. Set up a compiling draft in LaTeX; journal format is a later, checkable requirement, not the scientific starting point.
5. Rewrite **framework and experiment sections first**, then results, related work, intro, abstract and conclusion. Review `git diff` at each step.
6. Build all tables and figures from the committed D03–D07 outputs; verify every numerical statement and the exact eligible population.
7. Decide the validation gate before submission, then check journal-specific anonymity, declarations, artifact policy and LaTeX requirements against current official JISA guidance.

## 9. Literature points requiring careful positioning

Original paper citation keys include `landauer2022alert_flooding`, `ghadermazi2024alert_management`, `rosso2022saibersoc`, `mitre_attack`, `mordor_empire_mimikatz`, and `mordor`. Further literature to verify and add for comparative framing:

- Landauer et al., *Dealing with Security Alert Flooding: Using Machine Learning for Domain-independent Alert Aggregation*, ACM TOPS (2022), DOI: https://doi.org/10.1145/3510581 . Retains/merges semi-structured alert context; we do not claim to invent context-preserving aggregation.
- Hassan et al., *NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage*, NDSS (2019), https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/ . Uses causal provenance and historical context for triage, which we **do not** evaluate.
- *HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows*, IEEE S&P (2019), DOI: https://doi.org/10.1109/SP.2019.00026 . Correlates attack-related flows and outputs a high-level graph; not the same objective as the present representation audit.

These references establish prior scope, **not** automatically novelty for the proposed audit. A line-by-line comparative related-work pass is still required.

---

**Decision sought from authors:** Is the bounded methodological contribution above worth writing as a full JISA article, with an explicit unresolved specificity/negative-control limitation, or should the validation gate be resolved first? No new experimental or manuscript changes are performed by this plan.
