"""D04 regression tests for a fixed-source evidence-preservation experiment."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'run_d04_evidence_preservation.py'
spec = importlib.util.spec_from_file_location('d04_preservation', SCRIPT)
assert spec and spec.loader
d04 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d04)


def fixture_inventory():
    base = []
    for index in range(8):
        flag = index in (1, 5)
        agent = index == 5
        base.append({
            'source_event_id': f'source:{index:04}',
            'host': 'HOST1' if index < 6 else 'HOST2',
            'event_time_utc': f'2020-08-07T12:00:{index:02d}.000Z',
            'event_time_basis': 'source_UtcTime',
            '_seconds': d04.event_seconds(f'2020-08-07T12:00:{index:02d}.000Z'),
            'lsass_access': '1' if flag else '0',
            'powershell_lsass_access': '1' if agent else '0',
            'documented_agent_lsass_access': '1' if agent else '0',
            'evidence_class': 'documented_agent_access' if agent else 'lsass_process_access' if flag else 'none',
        })
    return base


def test_healthy_keeps_all_reference_evidence():
    summary, relevant = d04.evaluate_condition(fixture_inventory(), 'healthy', 0, None)
    assert summary['delivered_units'] == 8
    assert summary['lsass_physically_represented'] == 2
    assert summary['lsass_timely_identifiable'] == 2
    assert summary['agent_timely_identifiable'] == 1
    assert {r['outcome'] for r in relevant} == {'available_by_deadline'}


def test_complete_loss_cannot_invent_any_evidence():
    summary, relevant = d04.evaluate_condition(fixture_inventory(), 'loss', 1, 1)
    assert summary['source_records_represented'] == 0
    assert summary['lsass_physically_represented'] == 0
    assert summary['lsass_timely_identifiable'] == 0
    assert summary['agent_timely_identifiable'] == 0
    assert {r['outcome'] for r in relevant} == {'dropped'}


def test_loss_repeatable_with_seed():
    a = d04.evaluate_condition(fixture_inventory(), 'loss', .5, 9)
    b = d04.evaluate_condition(fixture_inventory(), 'loss', .5, 9)
    assert a == b
    assert len(a[1]) == 2  # fixed evidence audit population, not the delivered subset


def test_synthetic_delay_has_zero_effect_on_physical_retention():
    rows = fixture_inventory()
    summary, observed = d04.evaluate_condition(rows, 'delay', 240, 2)
    assert summary['source_records_represented'] == len(rows)
    assert summary['lsass_physically_represented'] == 2
    assert summary['lsass_timely_identifiable'] + summary['late_identifiable_lsass'] == 2
    assert all(r['outcome'] in ('available_by_deadline', 'late') for r in observed)


def test_aggregation_holds_physical_reference_constant_but_changes_observability():
    rows = fixture_inventory()
    count, count_detail = d04.evaluate_condition(rows, 'aggregation', 10, None, 'count_only')
    aware, aware_detail = d04.evaluate_condition(rows, 'aggregation', 10, None, 'provenance_preserving')
    assert count['source_records_represented'] == aware['source_records_represented'] == 8
    assert count['delivered_units'] == aware['delivered_units'] == 2
    assert count['lsass_physically_represented'] == aware['lsass_physically_represented'] == 2
    assert count['lsass_identifiably_available'] == 0
    assert aware['lsass_identifiably_available'] == 2
    assert all(x['group_id'] for x in count_detail + aware_detail)
    assert {x['outcome'] for x in count_detail} == {'contained_but_unidentifiable'}
    assert {x['outcome'] for x in aware_detail} == {'available_by_deadline'}


def test_serialized_aggregations_encode_policy_without_hidden_event_labels():
    inventory = fixture_inventory()
    coarse = d04.serialized_aggregation(inventory, 10, 'count_only')
    detailed = d04.serialized_aggregation(inventory, 10, 'provenance_preserving')
    assert len(coarse) == len(detailed) == 2
    assert all(not row['source_event_ids'] and not row['lsass_evidence_ids'] for row in coarse)
    assert any('source:0005' in row['documented_agent_evidence_ids'] for row in detailed)
    assert sum(row['source_record_count'] for row in detailed) == 8


def test_incompatible_projection_rejected():
    with pytest.raises(ValueError, match='Aggregation requires'):
        d04.evaluate_condition(fixture_inventory(), 'aggregation', 5, None)
    with pytest.raises(ValueError, match='Projection policy'):
        d04.evaluate_condition(fixture_inventory(), 'healthy', 0, None, 'count_only')


def test_invalid_timestamp_is_not_silently_imputed():
    with pytest.raises(ValueError, match='requires an explicit timestamp'):
        d04.event_seconds('')
    with pytest.raises(ValueError, match='timezone-aware'):
        d04.event_seconds('2020-08-07 12:00:00')


def test_reference_checksums_enforced(tmp_path):
    ref = tmp_path / 'reference'
    ref.mkdir()
    inv = ref / 'd03_source_event_inventory.csv'
    det = ref / 'd03_lsass_access_evidence.csv'
    rows = fixture_inventory()
    fields = [k for k in rows[0] if k != '_seconds']
    with inv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: row[k] for k in fields} for row in rows)
    with det.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: row[k] for k in fields} for row in rows if row['lsass_access'] == '1')
    manifest = {'experiment': 'D03_fixed_source_evidence_inventory',
                'counts': {'total_events': 8, 'lsass_access': 2,
                           'powershell_lsass_access': 1, 'documented_agent_lsass_access': 1},
                'outputs': {'inventory_sha256': d04.sha256_file(inv), 'evidence_sha256': d04.sha256_file(det)}}
    (ref / 'd03_evidence_manifest.json').write_text(json.dumps(manifest))
    loaded, _ = d04.load_reference(ref)
    assert len(loaded) == 8
    inv.write_text(inv.read_text() + '\n')
    with pytest.raises(ValueError, match='checksum mismatch'):
        d04.load_reference(ref)


def test_full_run_is_deterministic_against_bundled_d03(tmp_path):
    reference = Path(__file__).resolve().parents[1] / 'outputs' / 'd03_source_evidence'
    if not (reference / 'd03_evidence_manifest.json').exists():
        pytest.skip('D03 results not available in this checkout')
    first = d04.run(reference, tmp_path / 'one', seeds=(1, 2))
    second = d04.run(reference, tmp_path / 'two', seeds=(1, 2))
    assert first['outputs']['summary_sha256'] == second['outputs']['summary_sha256']
    assert first['outputs']['evidence_outcomes_sha256'] == second['outputs']['evidence_outcomes_sha256']
    assert first['outputs']['aggregation_projections_sha256'] == second['outputs']['aggregation_projections_sha256']
    assert first['observations']['condition_rows'] == 19
    assert first['observations']['evidence_outcome_rows'] == 76
