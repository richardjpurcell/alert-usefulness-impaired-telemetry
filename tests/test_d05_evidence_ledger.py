"""Regression and contract tests for D05's nonprobabilistic evidence ledger."""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from run_d04_evidence_preservation import event_seconds
spec = importlib.util.spec_from_file_location('d05_evidence_ledger', SCRIPT_DIR / 'run_d05_evidence_ledger.py')
assert spec and spec.loader
d05 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d05)


def fixture_inventory():
    rows = []
    for i in range(8):
        lsass = i in (1, 2, 4, 6)
        pwsh = i == 4
        stamp = f'2020-08-07T12:00:{i:02d}.000Z'
        rows.append({
            'source_event_id': f's:{i:03}', 'event_time_utc': stamp,
            '_seconds': event_seconds(stamp),
            'lsass_access': '1' if lsass else '0',
            'powershell_lsass_access': '1' if pwsh else '0',
            'documented_agent_lsass_access': '1' if pwsh else '0',
        })
    return rows


def test_healthy_ledger_distinguishes_new_repeated_and_irrelevant():
    summary, rows = d05.replay(fixture_inventory(), 'healthy', 0, None)
    assert (summary['new_claim_events'], summary['repeat_claim_events'], summary['no_claim_events']) == (2, 2, 4)
    assert summary['all_claim_count'] == summary['timely_claim_count'] == 3
    assert summary['first_claim_A_event_id'] == 's:001'
    assert summary['first_claim_B_event_id'] == summary['first_claim_C_event_id'] == 's:004'
    assert [r['outcome'] for r in rows] == ['new_claim','repeat_claim','new_claim','repeat_claim']


def test_no_delivery_produces_no_evidence_or_claims():
    summary, outcomes = d05.replay(fixture_inventory(), 'loss', 1, 1)
    assert summary['delivered_events'] == 0
    assert summary['all_claim_count'] == 0
    assert summary['timely_claim_count'] == 0
    assert summary['evidence_events_missing'] == 4
    assert {x['outcome'] for x in outcomes} == {'dropped'}


def test_nested_indicator_contract_is_enforced():
    r = fixture_inventory()[0]
    r['documented_agent_lsass_access'] = '1'
    with pytest.raises(ValueError, match='must imply PowerShell'):
        d05.evidence_claims(r)
    r['documented_agent_lsass_access'] = '0'
    r['powershell_lsass_access'] = '1'
    with pytest.raises(ValueError, match='must imply LSASS'):
        d05.evidence_claims(r)


def test_replay_invariant_count_and_fixed_reference_evidence_population():
    for condition, level, seed in [('healthy',0,None),('loss',.3,5),('delay',240,5)]:
        summary, outcomes = d05.replay(fixture_inventory(), condition, level, seed)
        assert summary['delivered_events'] == sum(summary[k] for k in ('new_claim_events','repeat_claim_events','no_claim_events'))
        assert len(outcomes) == 4
        assert summary['evidence_events_received']+summary['evidence_events_missing']==4


def test_delayed_events_can_update_full_ledger_even_after_deadline(monkeypatch):
    class AlwaysSelected:
        def random(self): return 0.0
    monkeypatch.setattr(d05.random, 'Random', lambda seed: AlwaysSelected())
    summary, outcomes = d05.replay(fixture_inventory(), 'delay', 240, 1)
    assert summary['all_claim_count'] == 3
    assert summary['timely_claim_count'] == 0
    assert summary['delivered_events'] == 8
    assert all(row['timely_new_claims'] == '' for row in outcomes)


def test_short_delay_keeps_timeline_complete(monkeypatch):
    class AlwaysSelected:
        def random(self): return 0.0
    monkeypatch.setattr(d05.random, 'Random', lambda seed: AlwaysSelected())
    summary, _ = d05.replay(fixture_inventory(), 'delay', 60, 1)
    assert summary['all_claim_count'] == summary['timely_claim_count'] == 3


def test_arrival_order_can_change_which_event_first_adds_claim(monkeypatch):
    # First source LSASS event is delayed, later PowerShell event is not.
    # D05 processes arrival order, which is different from source order.
    class OrderedDraws:
        def __init__(self): self.i = 0
        def random(self):
            self.i += 1
            return 0.0 if self.i == 2 else 1.0
    monkeypatch.setattr(d05.random, 'Random', lambda seed: OrderedDraws())
    rows = fixture_inventory()
    summary, outcomes = d05.replay(rows, 'delay', 240, 1)
    assert summary['first_claim_A_event_id'] == 's:002'
    assert summary['first_claim_B_event_id'] == 's:004'
    assert next(r for r in outcomes if r['source_event_id']=='s:001')['outcome']=='repeat_claim'


def test_rejects_invalid_condition_and_duplicate_ids():
    with pytest.raises(ValueError, match='supports'):
        d05.replay(fixture_inventory(), 'aggregation', 5, None)
    rows = fixture_inventory()
    rows[0]['source_event_id'] = rows[1]['source_event_id']
    with pytest.raises(ValueError, match='unique'):
        d05.replay(rows, 'healthy', 0, None)


def test_random_loss_reproducible():
    a = d05.replay(fixture_inventory(), 'loss', .3, 2)
    b = d05.replay(fixture_inventory(), 'loss', .3, 2)
    assert a == b


def test_manifest_condition_counts_are_stable():
    assert len(d05.generated_conditions()) == 61
    assert len(d05.generated_conditions((1,2))) == 13
    with pytest.raises(ValueError, match='unique'):
        d05.generated_conditions((1,1))


def test_full_run_reproducible_and_d04_compatible(tmp_path):
    root = Path(__file__).resolve().parents[1]
    ref = root / 'outputs/d03_source_evidence'
    if not (ref/'d03_evidence_manifest.json').exists():
        pytest.skip('D03 output reference unavailable')
    one = d05.run(ref, tmp_path/'a', (1,2))
    two = d05.run(ref, tmp_path/'b', (1,2))
    assert one['observations'] == {'condition_rows':13,'evidence_rows':52}
    assert one['outputs']['summary_sha256'] == two['outputs']['summary_sha256']
    assert one['outputs']['evidence_trace_sha256'] == two['outputs']['evidence_trace_sha256']
    with (tmp_path/'a'/'d05_ledger_summary.csv').open() as f:
        rows = list(csv.DictReader(f))
    assert rows[0]['new_claim_events'] == '2'
    assert rows[0]['repeat_claim_events'] == '2'
    assert rows[0]['no_claim_events'] == '6022'
    # D04's counts use the identical source-order random stream.
    d04_summary = root/'outputs/d04_evidence_preservation/d04_condition_summary.csv'
    if d04_summary.exists():
        with d04_summary.open() as f:
            old = {(r['condition'],r['level'],r['seed']):r for r in csv.DictReader(f)}
        for row in rows:
            other = old[(row['condition'],row['level'],row['seed'])]
            assert int(row['delivered_events']) == int(other['delivered_units'])
            assert int(row['claim_C_seen']) == int(other['agent_identifiably_available'])
            assert int(row['claim_C_timely']) == int(other['agent_timely_identifiable'])
