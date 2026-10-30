"""D04: controlled evidence preservation against a frozen D03 reference.

This is an evidence-availability audit, NOT a compromise-state or SOC decision
quality estimator. Missing source evidence is never reconstructed from a
condition's received stream. All experiments are deterministic under seeds.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_REFERENCE_DIR = Path('outputs/d03_source_evidence')
DEFAULT_OUTPUT_DIR = Path('outputs/d04_evidence_preservation')
WINDOW_SECONDS = (5, 10, 30)
LOSS_RATES = (0.10, 0.30, 0.50)
DELAY_SECONDS = (60, 240, 600)
AFFECTED_RATE = 0.30
DEADLINE_SECONDS = 180
SEEDS = tuple(range(1, 11))
EVIDENCE_FLAGS = ('lsass_access', 'powershell_lsass_access', 'documented_agent_lsass_access')
SUMMARY_COLUMNS = (
    'condition', 'level', 'seed', 'aggregation_policy', 'source_count',
    'delivered_units', 'source_records_represented', 'represented_fraction',
    'compression_ratio', 'lsass_physically_represented',
    'lsass_identifiably_available', 'lsass_timely_identifiable',
    'agent_physically_represented', 'agent_identifiably_available',
    'agent_timely_identifiable', 'late_identifiable_lsass',
)
AGGREGATION_COLUMNS = (
    'window_seconds', 'policy', 'group_id', 'host', 'source_record_count',
    'source_event_ids', 'lsass_evidence_ids', 'documented_agent_evidence_ids',
)
EVIDENCE_COLUMNS = (
    'condition', 'level', 'seed', 'aggregation_policy', 'source_event_id',
    'evidence_class', 'event_time_basis', 'outcome', 'synthetic_delay_seconds',
    'group_id',
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def event_seconds(value: str) -> float:
    if not value:
        raise ValueError('D04 requires an explicit timestamp for every source record')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError(f'Timestamp must be timezone-aware: {value!r}')
    return parsed.timestamp()


def load_reference(reference_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reject stale or altered references before running any experiments."""
    manifest_path = reference_dir / 'd03_evidence_manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('experiment') != 'D03_fixed_source_evidence_inventory':
        raise ValueError('Not a D03 source-evidence manifest')
    inv_file = reference_dir / 'd03_source_event_inventory.csv'
    evidence_file = reference_dir / 'd03_lsass_access_evidence.csv'
    for path, checksum_field in ((inv_file, 'inventory_sha256'), (evidence_file, 'evidence_sha256')):
        expected = manifest['outputs'][checksum_field]
        if sha256_file(path) != expected:
            raise ValueError(f'D03 fixed reference checksum mismatch: {path}')
    inventory = read_csv(inv_file)
    evidence_rows = read_csv(evidence_file)
    if len(inventory) != int(manifest['counts']['total_events']):
        raise ValueError('D03 source count differs from manifest')
    event_ids: set[str] = set()
    for event in inventory:
        uid = event['source_event_id']
        if uid in event_ids:
            raise ValueError(f'Duplicate immutable source_event_id: {uid}')
        event_ids.add(uid)
        event['_seconds'] = event_seconds(event['event_time_utc'])
        for flag in EVIDENCE_FLAGS:
            if event[flag] not in ('0', '1'):
                raise ValueError(f'Invalid indicator {flag} on {uid}')
    selected = {row['source_event_id'] for row in inventory if row['lsass_access'] == '1'}
    if selected != {row['source_event_id'] for row in evidence_rows} or len(evidence_rows) != len(selected):
        raise ValueError('Fixed inventory indicators disagree with D03 evidence detail table')
    for flag in EVIDENCE_FLAGS:
        if sum(int(event[flag]) for event in inventory) != int(manifest['counts'][flag]):
            raise ValueError(f'Indicator count mismatch for {flag}')
    return inventory, manifest


def aggregate_groups(inventory: list[dict[str, Any]], seconds: int) -> list[tuple[str, list[dict[str, Any]]]]:
    """Pure host/time grouping with fixed absolute UTC boundaries.

    Deliberately does not group by source event type or state, so count-only
    groups may contain both relevant evidence and unrelated records.
    """
    by_group: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in inventory:
        bucket = int(event['_seconds'] // seconds)
        by_group[(event['host'], bucket)].append(event)
    return [
        (f'{host}:{seconds}s:{bucket}', members)
        for (host, bucket), members in sorted(by_group.items())
    ]


def serialized_aggregation(inventory: list[dict[str, Any]], seconds: int,
                           policy: str) -> list[dict[str, Any]]:
    """Materialize what a downstream reader would actually see in each group."""
    if policy not in ('count_only', 'provenance_preserving'):
        raise ValueError(f'Unknown aggregation policy: {policy}')
    rows = []
    for group_id, members in aggregate_groups(inventory, seconds):
        ids = [r['source_event_id'] for r in members]
        evidence = [r['source_event_id'] for r in members if r['lsass_access'] == '1']
        agent = [r['source_event_id'] for r in members if r['documented_agent_lsass_access'] == '1']
        exposed = policy == 'provenance_preserving'
        rows.append({
            'window_seconds': seconds, 'policy': policy, 'group_id': group_id,
            'host': members[0]['host'], 'source_record_count': len(members),
            'source_event_ids': ';'.join(ids) if exposed else '',
            'lsass_evidence_ids': ';'.join(evidence) if exposed else '',
            'documented_agent_evidence_ids': ';'.join(agent) if exposed else '',
        })
    return rows


def evaluate_condition(
    inventory: list[dict[str, Any]], condition: str, level: int | float,
    seed: int | None, policy: str = 'none', deadline_seconds: int = DEADLINE_SECONDS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return audit summary and four fixed evidence-record outcomes per run.

    Physical representation is known *to the experiment* via source IDs, even
    when a count-only group does not expose those IDs to its downstream reader.
    Identifiability requires an event-level signature/identity to be retained.
    """
    if condition not in ('healthy', 'loss', 'delay', 'aggregation'):
        raise ValueError(f'Unknown condition {condition}')
    if condition == 'aggregation' and policy not in ('count_only', 'provenance_preserving'):
        raise ValueError('Aggregation requires an explicit projection policy')
    if condition != 'aggregation' and policy != 'none':
        raise ValueError('Projection policy applies only to aggregation')
    rng = random.Random(seed)
    retained_ids: set[str] = set()
    delay_by_id: dict[str, int] = {}
    groups_by_id: dict[str, str] = {}
    if condition == 'loss':
        if not 0 <= float(level) <= 1:
            raise ValueError('Loss rate must be between 0 and 1')
        for event in inventory:
            if rng.random() >= float(level):
                retained_ids.add(event['source_event_id'])
        delivered_units = len(retained_ids)
    elif condition == 'delay':
        if int(level) < 0:
            raise ValueError('Synthetic delay must be nonnegative')
        for event in inventory:
            uid = event['source_event_id']
            retained_ids.add(uid)
            delay_by_id[uid] = int(level) if rng.random() < AFFECTED_RATE else 0
        delivered_units = len(retained_ids)
    elif condition == 'aggregation':
        retained_ids = {event['source_event_id'] for event in inventory}
        groups = aggregate_groups(inventory, int(level))
        delivered_units = len(groups)
        for group_id, members in groups:
            for event in members:
                groups_by_id[event['source_event_id']] = group_id
    else:
        retained_ids = {event['source_event_id'] for event in inventory}
        delivered_units = len(retained_ids)
    reference_count = len(inventory)
    relevant_rows: list[dict[str, Any]] = []
    represented_lsass = 0
    identifiable_lsass = 0
    timely_lsass = 0
    late_lsass = 0
    represented_agent = 0
    identifiable_agent = 0
    timely_agent = 0
    for event in inventory:
        if event['lsass_access'] != '1':
            continue
        uid = event['source_event_id']
        present = uid in retained_ids
        identifiable = present and (condition != 'aggregation' or policy == 'provenance_preserving')
        simulated_lag = delay_by_id.get(uid, 0)
        timely = identifiable and simulated_lag <= deadline_seconds
        represented_lsass += int(present)
        identifiable_lsass += int(identifiable)
        timely_lsass += int(timely)
        late_lsass += int(identifiable and not timely)
        agent = event['documented_agent_lsass_access'] == '1'
        represented_agent += int(agent and present)
        identifiable_agent += int(agent and identifiable)
        timely_agent += int(agent and timely)
        outcome = (
            'dropped' if not present else
            'contained_but_unidentifiable' if not identifiable else
            'late' if not timely else 'available_by_deadline'
        )
        relevant_rows.append({
            'condition': condition, 'level': level, 'seed': '' if seed is None else seed,
            'aggregation_policy': policy, 'source_event_id': uid,
            'evidence_class': event['evidence_class'],
            'event_time_basis': event['event_time_basis'],
            'outcome': outcome, 'synthetic_delay_seconds': simulated_lag,
            'group_id': groups_by_id.get(uid, ''),
        })
    return ({
        'condition': condition, 'level': level, 'seed': '' if seed is None else seed,
        'aggregation_policy': policy, 'source_count': reference_count,
        'delivered_units': delivered_units,
        'source_records_represented': len(retained_ids),
        'represented_fraction': round(len(retained_ids) / reference_count, 6),
        'compression_ratio': round(reference_count / delivered_units, 6) if delivered_units else None,
        'lsass_physically_represented': represented_lsass,
        'lsass_identifiably_available': identifiable_lsass,
        'lsass_timely_identifiable': timely_lsass,
        'agent_physically_represented': represented_agent,
        'agent_identifiably_available': identifiable_agent,
        'agent_timely_identifiable': timely_agent,
        'late_identifiable_lsass': late_lsass,
    }, relevant_rows)


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run(reference_dir: Path = DEFAULT_REFERENCE_DIR, output_dir: Path = DEFAULT_OUTPUT_DIR,
        seeds: tuple[int, ...] = SEEDS) -> dict[str, Any]:
    inventory, d03_manifest = load_reference(reference_dir)
    if not inventory:
        raise ValueError('Empty inventory')
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError('Seeds must be nonempty and unique')
    summaries: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    group_projections: list[dict[str, Any]] = []
    conditions: list[tuple[str, int | float, int | None, str]] = [('healthy', 0, None, 'none')]
    for rate in LOSS_RATES:
        for seed in seeds:
            conditions.append(('loss', rate, seed, 'none'))
    for seconds in DELAY_SECONDS:
        for seed in seeds:
            conditions.append(('delay', seconds, seed, 'none'))
    for window in WINDOW_SECONDS:
        for projection in ('count_only', 'provenance_preserving'):
            conditions.append(('aggregation', window, None, projection))
    for mode, level, seed, policy in conditions:
        row, details = evaluate_condition(inventory, mode, level, seed, policy)
        summaries.append(row)
        observations.extend(details)
        if mode == 'aggregation':
            group_projections.extend(serialized_aggregation(inventory, int(level), policy))
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / 'd04_condition_summary.csv'
    detail_path = output_dir / 'd04_fixed_evidence_outcomes.csv'
    groups_path = output_dir / 'd04_aggregation_projections.csv'
    manifest_path = output_dir / 'd04_experiment_manifest.json'
    write_csv(groups_path, AGGREGATION_COLUMNS, group_projections)
    write_csv(summary_path, SUMMARY_COLUMNS, summaries)
    write_csv(detail_path, EVIDENCE_COLUMNS, observations)
    manifest = {
        'experiment': 'D04_evidence_preservation_under_impairment',
        'purpose': 'fixed-evidence availability and identifiability; no host-compromise truth or analyst usefulness',
        'reference': {
            'd03_experiment': d03_manifest['experiment'],
            'd03_manifest_sha256': sha256_file(reference_dir / 'd03_evidence_manifest.json'),
            'inventory_sha256': d03_manifest['outputs']['inventory_sha256'],
            'evidence_sha256': d03_manifest['outputs']['evidence_sha256'],
            'source_count': d03_manifest['counts']['total_events'],
            'lsass_count': d03_manifest['counts']['lsass_access'],
            'documented_agent_count': d03_manifest['counts']['documented_agent_lsass_access'],
        },
        'parameters': {
            'loss_rates': list(LOSS_RATES), 'delay_seconds': list(DELAY_SECONDS),
            'affected_fraction': AFFECTED_RATE, 'deadline_seconds': DEADLINE_SECONDS,
            'aggregation_windows_seconds': list(WINDOW_SECONDS),
            'aggregation_group_keys': ['host', 'absolute_UTC_time_bucket'],
            'aggregation_policies': ['count_only', 'provenance_preserving'],
            'seeds': list(seeds), 'random_draw_order': 'D03 source-inventory row order',
            'synthetic_baseline_latency_seconds': 0,
        },
        'observations': {
            'condition_rows': len(summaries),
            'evidence_outcome_rows': len(observations),
            'aggregation_projection_rows': len(group_projections),
            'source_timestamp_bases': d03_manifest['event_time_bases'],
        },
        'definitions': {
            'physical_representation': 'at least the source identity is included in the experiment-side received source set or aggregate group',
            'identifiable': 'source event identity and D03 structured indicator remain available to the audit consumer',
            'timely': 'identifiable and synthetic delivery shift <= 180 seconds after D03 event_time_utc',
            'count_only': 'group contains only host/time/count, with no recoverable source IDs or structured evidence indicators',
            'provenance_preserving': 'group retains per-member source IDs and relevant D03 evidence annotations',
        },
        'caveats': [
            'The four D03 LSASS events are a declared evidence subset, not compromise ground truth.',
            'Loss and delay are synthetic; the baseline assumes zero transport latency and therefore does not measure actual SOC availability.',
            'D03 uses labelled index timestamp fallback for some records; cross-record event-time interpretation may be affected.',
            'The contrasting aggregation projections are deliberately constructed controls, not evaluated commercial aggregators.',
            'Whether evidence is identifiable under aggregation is determined by the projection policy, not independently observed detection success.',
            'A single documented-agent evidence record makes its survival highly variable under random loss.',
            'No statistical generalization to operational SOC telemetry is implied by the 10 fixed random seeds.',
        ],
        'outputs': {
            'summary': summary_path.as_posix(), 'summary_sha256': sha256_file(summary_path),
            'evidence_outcomes': detail_path.as_posix(), 'evidence_outcomes_sha256': sha256_file(detail_path),
            'aggregation_projections': groups_path.as_posix(), 'aggregation_projections_sha256': sha256_file(groups_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-dir', type=Path, default=DEFAULT_REFERENCE_DIR)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    manifest = run(args.reference_dir, args.output_dir)
    print(json.dumps({'reference': manifest['reference'], 'observations': manifest['observations'],
                      'outputs': manifest['outputs']}, indent=2))


if __name__ == '__main__':
    main()
