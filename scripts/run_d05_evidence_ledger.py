"""D05: event-arrival evidence ledger over a fixed D03 source reference.

The ledger records *declared evidence claims*, not probabilities, compromise
truth, operational alert usefulness, or inferred absence of attack. This first
stage covers unaggregated healthy, loss and synthetic-delay replays. Aggregated
D04 projections do not yet retain sufficient structured fields for an honest
claim-reconstruction experiment; that is a separate subsequent question.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path
from typing import Any

from run_d04_evidence_preservation import (
    AFFECTED_RATE, DEADLINE_SECONDS, DELAY_SECONDS, LOSS_RATES, SEEDS,
    DEFAULT_REFERENCE_DIR, load_reference, sha256_file,
)

DEFAULT_OUTPUT_DIR = Path('outputs/d05_evidence_ledger')
CLAIMS = ('lsass_access', 'powershell_lsass_access', 'documented_agent_lsass_access')
SUMMARY_COLUMNS = (
    'condition', 'level', 'seed', 'source_count', 'delivered_events',
    'delivered_fraction', 'evidence_events_received', 'evidence_events_missing',
    'new_claim_events', 'repeat_claim_events', 'no_claim_events',
    'all_claim_count', 'timely_claim_count',
    'claim_A_seen', 'claim_B_seen', 'claim_C_seen',
    'claim_A_timely', 'claim_B_timely', 'claim_C_timely',
    'first_claim_A_event_id', 'first_claim_B_event_id', 'first_claim_C_event_id',
)
EVIDENCE_COLUMNS = (
    'condition', 'level', 'seed', 'source_event_id', 'source_event_time_utc',
    'arrival_time_utc', 'synthetic_delay_seconds', 'outcome',
    'new_claims', 'previous_claims', 'timely_new_claims',
    'claims_after', 'timely_claims_after',
)


def generated_conditions(seeds: tuple[int, ...] = SEEDS) -> list[tuple[str, int | float, int | None]]:
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError('Seeds must be nonempty and unique')
    return ([('healthy', 0, None)]
            + [('loss', rate, seed) for rate in LOSS_RATES for seed in seeds]
            + [('delay', seconds, seed) for seconds in DELAY_SECONDS for seed in seeds])


def evidence_claims(event: dict[str, Any]) -> set[str]:
    """D03 observations plus a clearly identified scenario-documentation join.

    Flag C is a scenario-specific documented-agent match, NOT an independent
    detector outcome. The nested D03 flags are enforced rather than assumed.
    """
    flags = {claim for claim in CLAIMS if event[claim] == '1'}
    if 'documented_agent_lsass_access' in flags and 'powershell_lsass_access' not in flags:
        raise ValueError('Documented-agent flag must imply PowerShell access')
    if 'powershell_lsass_access' in flags and 'lsass_access' not in flags:
        raise ValueError('PowerShell access must imply LSASS access')
    return flags


def replay(inventory: list[dict[str, Any]], condition: str, level: int | float,
           seed: int | None, deadline: int = DEADLINE_SECONDS
           ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if condition not in ('healthy', 'loss', 'delay'):
        raise ValueError('D05 currently supports healthy, loss and delay only')
    if deadline < 0:
        raise ValueError('Deadline must be nonnegative')
    if condition == 'loss' and not 0 <= float(level) <= 1:
        raise ValueError('Loss probability outside [0,1]')
    if condition == 'delay' and int(level) < 0:
        raise ValueError('Delay must be nonnegative')
    ids = [r['source_event_id'] for r in inventory]
    if len(ids) != len(set(ids)):
        raise ValueError('Source-event IDs must be unique')
    rng = random.Random(seed)
    delivered: list[tuple[float, str, dict[str, Any], int]] = []
    for event in inventory:
        # Preserve D04 random draw order: *one draw for every D03 inventory row*.
        if condition == 'loss' and rng.random() < float(level):
            continue
        delay = int(level) if condition == 'delay' and rng.random() < AFFECTED_RATE else 0
        delivered.append((event['_seconds'] + delay, event['source_event_id'], event, delay))
    # Arrival order, not input order: delays may reorder events.
    delivered.sort(key=lambda item: (item[0], item[1]))
    ledger: set[str] = set()
    timely_ledger: set[str] = set()
    first_source: dict[str, str] = {}
    event_results: dict[str, dict[str, Any]] = {}
    new_events = repeated_events = irrelevant_events = 0
    for arrival, uid, event, delay in delivered:
        claims = evidence_claims(event)
        novel = claims - ledger
        already = claims & ledger
        # Apply both ledgers in the SAME arrival order. A late event remains
        # available in the complete ledger but does not enter timely state.
        timely_novel = claims - timely_ledger if delay <= deadline else set()
        if novel:
            new_events += 1
        elif claims:
            repeated_events += 1
        else:
            irrelevant_events += 1
        for claim in sorted(novel):
            first_source[claim] = uid
        ledger.update(claims)
        timely_ledger.update(timely_novel)
        if 'lsass_access' in claims:
            from datetime import datetime, timezone
            event_results[uid] = {
                'source_event_id': uid,
                'source_event_time_utc': event['event_time_utc'],
                'arrival_time_utc': datetime.fromtimestamp(arrival, tz=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
                'synthetic_delay_seconds': delay,
                'outcome': 'new_claim' if novel else 'repeat_claim',
                'new_claims': ';'.join(sorted(novel)),
                'previous_claims': ';'.join(sorted(already)),
                'timely_new_claims': ';'.join(sorted(timely_novel)),
                'claims_after': ';'.join(sorted(ledger)),
                'timely_claims_after': ';'.join(sorted(timely_ledger)),
            }
    evidence_rows: list[dict[str, Any]] = []
    for event in inventory:
        if event['lsass_access'] != '1':
            continue
        uid = event['source_event_id']
        outcome = event_results.get(uid)
        if outcome is None:
            outcome = {key: '' for key in EVIDENCE_COLUMNS}
            outcome.update(source_event_id=uid,
                           source_event_time_utc=event['event_time_utc'],
                           outcome='dropped')
        evidence_rows.append({'condition': condition, 'level': level,
                              'seed': '' if seed is None else seed, **outcome})
    received_evidence = len(event_results)
    summary = {
        'condition': condition, 'level': level, 'seed': '' if seed is None else seed,
        'source_count': len(inventory), 'delivered_events': len(delivered),
        'delivered_fraction': round(len(delivered)/len(inventory), 6) if inventory else None,
        'evidence_events_received': received_evidence,
        'evidence_events_missing': len(evidence_rows) - received_evidence,
        'new_claim_events': new_events, 'repeat_claim_events': repeated_events,
        'no_claim_events': irrelevant_events,
        'all_claim_count': len(ledger), 'timely_claim_count': len(timely_ledger),
        **{f'claim_{suffix}_seen': int(claim in ledger)
           for suffix, claim in zip('ABC', CLAIMS)},
        **{f'claim_{suffix}_timely': int(claim in timely_ledger)
           for suffix, claim in zip('ABC', CLAIMS)},
        **{f'first_claim_{suffix}_event_id': first_source.get(claim, '')
           for suffix, claim in zip('ABC', CLAIMS)},
    }
    if new_events + repeated_events + irrelevant_events != len(delivered):
        raise AssertionError('Event-outcome partition does not match delivery count')
    if len(evidence_rows) != sum(int(e['lsass_access']) for e in inventory):
        raise AssertionError('Fixed evidence outcome population changed')
    return summary, evidence_rows


def write_csv(path: Path, columns: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def run(reference_dir: Path = DEFAULT_REFERENCE_DIR, output_dir: Path = DEFAULT_OUTPUT_DIR,
        seeds: tuple[int, ...] = SEEDS) -> dict[str, Any]:
    inventory, d03_manifest = load_reference(reference_dir)
    if not inventory:
        raise ValueError('D05 requires nonempty fixed reference')
    summary_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    for condition, level, seed in generated_conditions(seeds):
        summary, evidence = replay(inventory, condition, level, seed)
        summary_rows.append(summary)
        evidence_rows.extend(evidence)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = output_dir / 'd05_ledger_summary.csv'
    detail_file = output_dir / 'd05_evidence_update_trace.csv'
    manifest_file = output_dir / 'd05_ledger_manifest.json'
    write_csv(summary_file, SUMMARY_COLUMNS, summary_rows)
    write_csv(detail_file, EVIDENCE_COLUMNS, evidence_rows)
    manifest = {
        'experiment': 'D05_maintained_evidence_ledger',
        'purpose': 'declared claim acquisition under raw event replay; not belief accuracy or SOC usefulness',
        'reference': {
            'd03_manifest_sha256': sha256_file(reference_dir / 'd03_evidence_manifest.json'),
            'inventory_sha256': d03_manifest['outputs']['inventory_sha256'],
            'evidence_sha256': d03_manifest['outputs']['evidence_sha256'],
            'source_count': len(inventory),
        },
        'claim_definitions': {
            'A': 'Sysmon EventID 10 TargetImage lsass.exe (D03 structured indicator)',
            'B': 'A plus SourceImage powershell.exe',
            'C': 'B plus documented WORKSTATION5 / Empire PowerShell agent PID association',
        },
        'parameters': {
            'loss_rates': list(LOSS_RATES), 'delay_seconds': list(DELAY_SECONDS),
            'affected_fraction': AFFECTED_RATE, 'deadline_seconds': DEADLINE_SECONDS,
            'seeds': list(seeds), 'baseline_synthetic_delay_seconds': 0,
            'random_draw_order': 'D03 source-inventory row order (D04-compatible)',
            'replay_order': 'synthetic arrival timestamp, source ID as tie-breaker',
            'aggregation': 'excluded pending structured-field retention design',
        },
        'definitions': {
            'new_claim_event': 'event supports at least one claim not in complete ledger just before arrival',
            'repeat_claim_event': 'event supports one or more claims, none new to complete ledger',
            'no_claim_event': 'event supplies none of the declared claims',
            'complete_ledger': 'monotonic set union of arrived source-record claims',
            'timely_ledger': 'monotonic set union of arrived claims whose synthetic delay is <= deadline',
            'missing_event': 'fixed-reference evidence record not delivered; no inferred substitute',
        },
        'limitations': [
            'The three claims are nested by construction, not independent evidence of compromise.',
            'C is scenario-documentation-assisted and is not a general SOC-detectable claim.',
            'Novel claim acquisition is a ledger-definition consequence, not a validated usefulness score.',
            'Repetition of a claim does not mean a record is operationally worthless or independent corroboration absent.',
            'A monotonic claim set cannot handle contradiction, revocation, decay, provenance trust or negative evidence.',
            'D03 event timestamps mix 679 source UtcTime and 5347 indexed-time fallbacks; cross-source ordering is limited.',
            'No source-side/production transport latency is inferred; synthetic delay is relative to selected D03 timestamp.',
            'This first D05 test deliberately excludes aggregation; D04 aggregation projections do not expose independent structured fields sufficient for a fair reclassification.',
        ],
        'observations': {'condition_rows': len(summary_rows), 'evidence_rows': len(evidence_rows)},
        'outputs': {
            'summary': summary_file.as_posix(), 'summary_sha256': sha256_file(summary_file),
            'evidence_trace': detail_file.as_posix(), 'evidence_trace_sha256': sha256_file(detail_file),
        },
    }
    manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-dir', type=Path, default=DEFAULT_REFERENCE_DIR)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    result = run(args.reference_dir, args.output_dir)
    print(json.dumps({'reference': result['reference'],
                      'observations': result['observations'],
                      'outputs': result['outputs']}, indent=2))


if __name__ == '__main__':
    main()
