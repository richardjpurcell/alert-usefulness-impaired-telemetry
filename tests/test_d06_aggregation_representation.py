"""D06 acceptance tests: joint-field grouping, oracle separation, provenance and timing."""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPT))
import run_d06_aggregation_representation as d06


def sample(uid: str, second: float, source: str, target: str, pid: str,
           event_id: int = 10, host: str = 'workstation5', basis: str = 'source_UtcTime'):
    return {'uid':uid, 'host':host, 'time':second, 'basis':basis,
            'record':{'Hostname':host,'EventID':event_id, 'SourceImage':source,
                      'TargetImage':target,'SourceProcessId':pid}}


def fixture():
    return [sample('a',100.1,r'C:\Windows\powershell.exe',r'C:\Other\benign.exe','1648'),
            sample('b',100.3,r'C:\Windows\svchost.exe',r'C:\Windows\System32\lsass.exe','555'),
            sample('c',100.4,r'C:\Windows\POWERSHELL.EXE',r'C:\Windows\System32\LSASS.EXE','1648'),
            sample('d',100.5,'','','',event_id=1,basis='index_timestamp_fallback')]


def encode(events, policy, window=5):
    group = d06.group_events(events,window)[0]
    return d06.encode_group(group,policy)


def decode(row):
    return d06.decode_row(d06.compact_json(row).encode('utf-8'))


def test_joint_tuples_do_not_invent_cross_product():
    evs=fixture()[:2]
    assert decode(encode(evs,'P2_joint')) == {'A':'supported','B':'unsupported','C':'unsupported'}
    assert decode(encode(evs,'P3_pid')) == {'A':'supported','B':'unsupported','C':'unsupported'}


def test_normalized_tuples_and_nested_claims():
    evs=fixture()
    p2=encode(evs,'P2_joint')
    p3=encode(evs,'P3_pid')
    assert decode(p2)== {'A':'supported','B':'supported','C':'indeterminate'}
    assert decode(p3)== {'A':'supported','B':'supported','C':'supported'}
    assert all(t[1]==t[1].lower() and t[2]==t[2].lower() for t in p3['process_access'])
    assert p3['count']==4
    assert dict(p3['event_histogram'])=={'1':1,'10':3}


def test_repetition_keeps_multiplicity():
    evs=[fixture()[2], copy.deepcopy(fixture()[2])]
    p3=encode(evs,'P3_pid')
    assert p3['process_access'][0][-1]==2
    assert len(p3['process_access'])==1


def test_count_only_is_indeterminate_not_false():
    assert decode(encode(fixture(),'P1_count'))==dict.fromkeys(d06.CLAIMS,'indeterminate')


def test_encoder_cannot_use_d03_labels():
    evs=fixture()
    reference=[d06.compact_json(encode(evs,p)) for p in d06.POLICIES]
    for idx,ev in enumerate(evs):
        ev['record'].update({'lsass_access': '1' if idx==0 else '0',
                             'documented_agent_lsass_access':'1','evidence_class':'compromised'})
        ev.update({'lsass_access':'1','powershell_lsass_access':'1'})
    assert reference==[d06.compact_json(encode(evs,p)) for p in d06.POLICIES]


def test_decoding_only_serialized_fields_and_no_source_ids():
    for policy in d06.POLICIES:
        encoded=encode(fixture(),policy)
        assert 'source_event_id' not in d06.compact_json(encoded)
        assert 'uid' not in encoded
        assert isinstance(decode(encoded),dict)


def test_missing_images_remain_indeterminate():
    evs=[sample('missing',100.1,'','','1648')]
    for policy in ('P2_joint','P3_pid'):
        out=decode(encode(evs,policy))
        assert out['A']==out['B']==out['C']=='indeterminate'


def test_missing_pid_is_not_agent_evidence():
    evs=[sample('missing_pid',100.1,'powershell.exe','lsass.exe','')]
    assert decode(encode(evs,'P3_pid'))=={'A':'supported','B':'supported','C':'indeterminate'}


def test_other_host_cannot_match_scenario_agent():
    evs=[sample('other',100.1,'powershell.exe','lsass.exe','1648',host='workstation6')]
    assert decode(encode(evs,'P3_pid'))=={'A':'supported','B':'supported','C':'unsupported'}


def test_event10_histogram_reconciliation_is_checked():
    row=encode(fixture(),'P3_pid')
    row['process_access']=[]
    with pytest.raises(ValueError,match='incomplete'):
        decode(row)


def test_utc_tumbling_window_boundary_and_fallback_basis():
    evs=[sample('early',100.001,'a','b','1'),sample('late',104.999,'a','b','1'),
         sample('next',105.0,'a','b','1',basis='index_timestamp_fallback')]
    groups=d06.group_events(evs,5)
    assert [len(g['members']) for g in groups]==[2,1]
    first=d06.encode_group(groups[0],'P3_pid')
    second=d06.encode_group(groups[1],'P3_pid')
    assert first['end']==d06.utc_iso(105)
    assert second['source_utc_range'] is None
    assert 105-104.999 < 5
    assert 105-100.001 < 5
    assert 105-100.001 > 4


def test_raw_no_invented_record_identity_and_decoder_consistency():
    ev=fixture()[2]
    original=d06.encode_raw([ev])[0]
    assert original['source_event_id']=='c'
    decoded=d06.decode_raw_row(d06.compact_json(original).encode('utf-8'))
    assert decoded==dict.fromkeys(d06.CLAIMS,'supported')


def test_reference_integrity_and_reproducibility(tmp_path):
    archive = d06.DEFAULT_ARCHIVE
    reference = d06.DEFAULT_REF
    if not archive.exists() or not reference.exists():
        pytest.skip('Raw archive and frozen D03 reference unavailable')
    events, manifest = d06.read_source(archive,reference)
    assert len(events)==6026
    assert sum(d06.as_event_id(x['record'])=='10' for x in events)==272
    assert sum(e['basis']=='source_UtcTime' for e in events)==679
    assert sum(e['basis']=='index_timestamp_fallback' for e in events)==5347
    with (reference/'d03_source_event_inventory.csv').open() as f:
        import csv
        inventory=list(csv.DictReader(f))
    files,summaries,rows=d06.build_rows(events,inventory)
    assert len(files)==10 and len(summaries)==10 and len(rows)>0
    assert summaries[0]['A_supported']==4
    assert summaries[0]['B_supported']==summaries[0]['C_supported']==1
    assert all(r['false_supported']==r['false_excluded']==0 for r in summaries)
    assert all(r['C_event_id_recovered']==0 for r in summaries[1:])
    assert all(r['C_ledger_present']==1 for r in summaries if r['policy']=='P3_pid')
    assert all(r['C_ledger_present']==0 for r in summaries if r['policy']=='P2_joint')
    out1=tmp_path/'one'
    out2=tmp_path/'two'
    d06.run(archive,reference,out1)
    d06.run(archive,reference,out2)
    files1={str(p.relative_to(out1)):p.read_bytes() for p in out1.rglob('*') if p.is_file()}
    files2={str(p.relative_to(out2)):p.read_bytes() for p in out2.rglob('*') if p.is_file()}
    assert files1==files2
    # Mutation of source archive rejected by source SHA-256 before decoding.
    modified=tmp_path/'tampered.zip'
    modified.write_bytes(archive.read_bytes()+b'bad')
    with pytest.raises(ValueError,match='archive SHA-256'):
        d06.read_source(modified,reference)
