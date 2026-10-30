"""D08 negative, positive and information-withholding reconstruction controls."""
import json
import sys
from pathlib import Path

import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import run_d08_claim_discrimination as d08
from run_d06_aggregation_representation import encode_group,group_events,to_jsonl,decode_row
from run_d07_transfer_comparison import decode_transfer

CASES=Path(__file__).resolve().parents[1]/'configs/d08_claim_unit_cases.json'


def sample(event_id=10,source='powershell.exe',target='lsass.exe',pid='1648',time=1596810760.0):
    return {'uid':'unit','record':{'EventID':event_id,'SourceImage':source,
            'TargetImage':target,'SourceProcessId':pid,'Hostname':'WORKSTATION5'},
            'host':'workstation5','basis':'source_UtcTime','time':time}


def encode(events,policy):
    group=group_events(events,5)
    assert len(group)==1
    return to_jsonl([encode_group(group[0],policy)]).strip()


def test_frozen_case_design_is_24_and_balanced():
    locked=json.loads(CASES.read_text())
    assert locked['policy_window_seconds']==5
    assert len(locked['cases'])==24
    assert len({c['id'] for c in locked['cases']})==24
    assert sum(c['scenario']=='mimikatz' for c in locked['cases'])==12
    assert sum(c['scenario']=='comsvcs' for c in locked['cases'])==12


def test_case_design_has_three_expected_states():
    locked=json.loads(CASES.read_text())
    assert {c['expected'] for c in locked['cases']} == d08.STATES
    assert any(c.get('withheld_fields') for c in locked['cases'])
    assert any(len(c['source_lines'])==2 for c in locked['cases'])


def test_missing_image_keeps_positive_target_but_abstains_on_source():
    ev=sample()
    ev['record'].pop('SourceImage')
    decoded=decode_row(encode([ev],'P2_joint'))
    assert decoded['A']=='supported'
    assert decoded['B']=='indeterminate'


def test_no_fabricated_joint_relation_from_actual_pair_pattern():
    a=sample(source='powershell.exe',target='whoami.exe')
    b=sample(source='svchost.exe',target='lsass.exe')
    assert decode_row(encode([a,b],'P2_joint'))['B']=='unsupported'


def test_pid_removed_is_indeterminate_even_with_other_support():
    assert decode_row(encode([sample()],'P2_joint')) == {
        'A':'supported','B':'supported','C':'indeterminate'}


def test_pid_retained_supports_agent_association():
    assert decode_row(encode([sample()],'P3_pid'))['C']=='supported'


def test_process_creation_not_recognized_by_locked_joint_aggregation():
    ev=sample(event_id=1)
    ev['record']={'EventID':1,'Image':'rundll32.exe',
                  'CommandLine':'comsvcs.dll MiniDump 756 out.dmp'}
    for policy in ('P2_joint','P3_pid'):
        assert decode_transfer(encode([ev],policy))['T3']=='indeterminate'


def test_t3_unsupported_when_complete_histogram_proves_no_process_creation():
    assert decode_transfer(encode([sample()],'P2_joint'))['T3']=='unsupported'


def test_binary_baseline_collapses_missing_and_negative():
    witness=sample()
    absent=sample(source='svchost.exe',target='other.exe')
    unknown=decode_row(encode([witness],'P1_count'))['A']
    negative=decode_row(encode([absent],'P2_joint'))['A']
    assert unknown=='indeterminate' and negative=='unsupported'
    assert (unknown!='supported') == (negative!='supported')


def test_limited_evaluation_reports_failures_without_tuning():
    # Minimal maps: one source witness is erroneously assumed absent.
    ev=sample()
    m={1:ev}
    row={'id':'X','scenario':'mimikatz','source_lines':[1], 'claim':'A',
         'policy':'P1_count','source_witness':True,'expected':'supported'}
    flags={'unit':{'lsass_access':'1'}}
    outcome=d08.one_case(row,m,{},flags)
    assert outcome['agreement']==0
    assert outcome['reconstructed']=='indeterminate'
    assert outcome['binary_false_excluded']==1


def test_requires_real_5s_window_not_arbitrary_aggregation():
    m={1:sample(time=1596810760.), 2:sample(time=1596810770.)}
    row={'id':'X','scenario':'mimikatz','source_lines':[1,2], 'claim':'A',
         'policy':'P2_joint','source_witness':True,'expected':'supported'}
    flags={'unit':{'lsass_access':'1'}}
    with pytest.raises(ValueError,match='one actual 5s'):
        d08.one_case(row,m,{},flags)
