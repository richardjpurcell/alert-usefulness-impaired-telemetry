"""D07 locked encoder transfer: independent claims, no hidden fields and time scope."""
from __future__ import annotations
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import run_d07_transfer_comparison as d07
from run_d06_aggregation_representation import encode_group, group_events, to_jsonl
from run_d07_scenario_preflight import inspect_zip


def rec(eid, source='',target='',image='',command='',pid='4824',utc='2020-10-18 23:50:05.910'):
    r={'EventID':eid,'Hostname':'WORKSTATION5'}
    if utc:r['UtcTime']=utc
    if eid==10:r.update(SourceImage=source,TargetImage=target,SourceProcessId=pid)
    if eid==1:r.update(Image=image,CommandLine=command,ProcessId=pid)
    return r


def encoded(records,policy='P3_pid'):
    events=[{'uid':str(i),'record':record,'time':1603065005.0+i/100,
             'host':'workstation5','basis':'source_UtcTime'} for i,record in enumerate(records)]
    group=group_events(events,5)[0]
    return to_jsonl([encode_group(group,policy)]).strip()


def test_source_claims_are_independent():
    cmd=rec(1,image=r'C:\Windows\rundll32.exe',command='comsvcs.dll MiniDump 756 out.dmp')
    access=rec(10,source=r'C:\Windows\rundll32.exe',target=r'C:\Windows\lsass.exe')
    assert d07.oracle_claims(cmd)=={'T1':False,'T2':False,'T3':True}
    assert d07.oracle_claims(access)=={'T1':True,'T2':True,'T3':False}


def test_no_cross_event_false_rundll():
    data=encoded([rec(10,source='rundll32.exe',target='other.exe'),
                  rec(10,source='svchost.exe',target='lsass.exe')])
    assert d07.decode_transfer(data)=={'T1':'supported','T2':'unsupported','T3':'unsupported'}


def test_p1_always_indeterminate():
    data=encoded([rec(10,source='rundll32.exe',target='lsass.exe')],'P1_count')
    assert list(d07.decode_transfer(data).values())==['indeterminate']*3


def test_p2_p3_cannot_claim_t3():
    rows=[rec(10,source='rundll32.exe',target='lsass.exe'),
          rec(1,image='rundll32.exe',command='comsvcs.dll MiniDump 756 output.dmp')]
    for policy in ('P2_joint','P3_pid'):
        decoded=d07.decode_transfer(encoded(rows,policy))
        assert decoded=={'T1':'supported','T2':'supported','T3':'indeterminate'}


def test_absent_event1_excludes_t3_when_histogram_retained():
    assert d07.decode_transfer(encoded([rec(10,source='rundll32.exe',target='lsass.exe')]))['T3']=='unsupported'


def test_missing_process_fields_indeterminate():
    result=d07.decode_transfer(encoded([rec(10,source='',target='')]))
    assert result['T1']=='indeterminate' and result['T2']=='indeterminate'


def test_raw_reconstructs_t3_only_with_command():
    raw={'record':rec(1,image=r'C:\Windows\rundll32.exe',command='comsvcs.dll MiniDump 756 out.dmp')}
    assert d07.decode_raw_transfer(json.dumps(raw).encode())['T3']=='supported'
    raw['record']['CommandLine']=''
    assert d07.decode_raw_transfer(json.dumps(raw).encode())['T3']=='indeterminate'


def make_archive(tmp_path):
    records=[]
    for i in range(184):
        if i == 73:
            record=rec(10,source='rundll32.exe',target='lsass.exe',utc='2020-10-18 23:50:05.994')
        elif i == 75:
            record=rec(10,source='rundll32.exe',target='lsass.exe',utc='2020-10-18 23:50:05.963')
        elif i == 82:
            record=rec(7,utc='2020-10-18 23:50:05.947')
        elif i == 106:
            record=rec(1,image='rundll32.exe',command='comsvcs.dll MiniDump 756 out.dmp',utc='2020-10-18 23:50:05.910')
        elif i < 148:
            record=rec(10,source='svchost.exe',target='other.exe',utc=f'2020-10-18 23:50:{i%55:02d}.000')
        else:
            record=rec(4656,utc=None)
        records.append(record)
    archive=tmp_path/'test.zip'
    data=b''.join((json.dumps(r)+'\n').encode() for r in records)
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('test.json',data)
    preflight=inspect_zip(archive)
    preflight_path=tmp_path/'preflight.json'
    preflight_path.write_text(json.dumps(preflight))
    return archive, preflight_path


def test_end_to_end_synthetic_transfer(tmp_path):
    archive,preflight=make_archive(tmp_path)
    report=d07.run(archive,preflight,tmp_path/'out')
    assert report['total_records']==184
    assert report['source_timed_records']==148
    assert report['unknown_time_records']==36
    assert report['source_claims']=={'T1':2,'T2':2,'T3':1}
    rows=list(__import__('csv').DictReader((tmp_path/'out/d07_transfer_summary.csv').open()))
    assert len(rows)==10
    for row in rows:
        if row['policy'] in ('P2_joint','P3_pid'):
            assert int(row['T1_ledger_present'])==1
            assert int(row['T2_ledger_present'])==1
            assert int(row['T3_ledger_present'])==0
            assert int(row['false_supported'])==0 and int(row['false_excluded'])==0


def test_hash_mismatch_fails_before_processing(tmp_path):
    archive,preflight=make_archive(tmp_path)
    frozen=json.loads(preflight.read_text())
    frozen['source_archive_sha256']='0'*64
    preflight.write_text(json.dumps(frozen))
    with pytest.raises(ValueError,match='checksum'):
        d07.run(archive,preflight,tmp_path/'out')


def test_deterministic_outputs(tmp_path):
    archive,preflight=make_archive(tmp_path)
    a=d07.run(archive,preflight,tmp_path/'out_a')
    b=d07.run(archive,preflight,tmp_path/'out_b')
    assert a==b
    for name in ('d07_transfer_summary.csv','d07_claim_reconstruction.csv','d07_fixed_source_evidence.csv'):
        assert (tmp_path/'out_a'/name).read_bytes()==(tmp_path/'out_b'/name).read_bytes()
