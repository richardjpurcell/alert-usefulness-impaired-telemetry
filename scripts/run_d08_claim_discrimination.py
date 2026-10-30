"""D08: locked 24-case audit of supported / unsupported / indeterminate.

Uses the original, unchanged D06 encoders and D06/D07 decoders. Cases and expected
answers are frozen in configs/d08_claim_unit_cases.json. These are bounded
reconstruction-contract checks, not SOC performance or independently blind labels.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

from build_d03_source_evidence_inventory import sha256_file
from run_d04_evidence_preservation import load_reference, event_seconds
from run_d06_aggregation_representation import (
    DEFAULT_ARCHIVE as D03_ARCHIVE,
    DEFAULT_REF as D03_REF,
    decode_raw_row, decode_row, encode_group, encode_raw,
    group_events, read_source, to_jsonl,
)
from run_d07_transfer_comparison import (
    DEFAULT_ARCHIVE as D07_ARCHIVE,
    DEFAULT_PREFLIGHT as D07_PREFLIGHT,
    decode_raw_transfer, decode_transfer, oracle_claims, read_candidate,
)

DEFAULT_CASES = Path('configs/d08_claim_unit_cases.json')
DEFAULT_OUT = Path('outputs/d08_claim_discrimination')
CLAIM_FLAGS = {'A': 'lsass_access', 'B': 'powershell_lsass_access',
               'C': 'documented_agent_lsass_access'}
STATES = {'supported', 'unsupported', 'indeterminate'}


def source_truth(case: dict, d03_flags: dict, items: list[dict]) -> bool:
    """Reference oracle sees original records; never supplied to encoder."""
    if case['scenario'] == 'mimikatz':
        flag = CLAIM_FLAGS[case['claim']]
        return any(d03_flags[item['uid']][flag] == '1' for item in items)
    return any(oracle_claims(item['record'])[case['claim']] for item in items)


def assemble(case: dict, d03_by_line: dict, d07_by_line: dict) -> list[dict]:
    source = d03_by_line if case['scenario'] == 'mimikatz' else d07_by_line
    items = []
    for line in case['source_lines']:
        if line not in source:
            raise ValueError(f"Case {case['id']} refers to unknown source line {line}")
        original = source[line]
        if original['basis'] != 'source_UtcTime':
            raise ValueError(f"Case {case['id']} uses non-source-timed record {line}")
        rec = dict(original['record'])
        for field in case.get('withheld_fields', []):
            if field not in rec or not str(rec[field]).strip():
                raise ValueError(f"Case {case['id']}: cannot withhold missing field {field}")
            rec.pop(field)
        items.append({**original, 'record': rec, 'time': original.get('time') if original.get('time') is not None else event_seconds(original['event_time_utc'])})
    return items


def one_case(case: dict, d03_by_line: dict, d07_by_line: dict, d03_flags: dict) -> dict:
    items = assemble(case, d03_by_line, d07_by_line)
    original_items = [
        (d03_by_line if case['scenario']=='mimikatz' else d07_by_line)[line]
        for line in case['source_lines']
    ]
    oracle = source_truth(case, d03_flags, original_items)
    if oracle is not case['source_witness']:
        raise ValueError(f"Predeclared source witness mismatch in {case['id']}")
    if case['policy'] == 'P0_raw':
        if len(items) != 1:
            raise ValueError('P0_raw contract requires one event per audit unit')
        payload = to_jsonl(encode_raw(items))
        statuses = (decode_raw_row(payload.strip()) if case['scenario']=='mimikatz'
                    else decode_raw_transfer(payload.strip()))
    else:
        groups = group_events(items, 5)
        if len(groups) != 1:
            raise ValueError(f"Case {case['id']} does not fit in one actual 5s host/window")
        payload = to_jsonl([encode_group(groups[0], case['policy'])])
        statuses = (decode_row(payload.strip()) if case['scenario']=='mimikatz'
                    else decode_transfer(payload.strip()))
    result = statuses[case['claim']]
    if result not in STATES:
        raise ValueError(f'Invalid decoder state {result}')
    return {
        'case_id': case['id'], 'scenario': case['scenario'],
        'source_lines': ';'.join(map(str,case['source_lines'])),
        'claim': case['claim'], 'policy': case['policy'],
        'withheld_fields': ';'.join(case.get('withheld_fields',[])),
        'source_witness': int(oracle),
        'expected': case['expected'], 'reconstructed': result,
        'agreement': int(result == case['expected']),
        'false_supported': int(result=='supported' and not oracle),
        'false_excluded': int(result=='unsupported' and oracle),
        'source_witness_abstained': int(result=='indeterminate' and oracle),
        'source_nonwitness_abstained': int(result=='indeterminate' and not oracle),
        'binary_supported': int(result=='supported'),
        'binary_not_supported': int(result!='supported'),
        'binary_false_excluded': int(result!='supported' and oracle),
        'member_count': len(items), 'serialized_bytes': len(payload),
        'gzip_bytes': len(gzip.compress(payload, mtime=0)),
        'note':case.get('note',''),
    }


def evaluate_cases(cases: list[dict], d03_by_line: dict, d07_by_line: dict,
                   d03_flags: dict) -> tuple[list[dict],dict]:
    if len(cases) != 24 or len({c['id'] for c in cases}) != 24:
        raise ValueError('D08 requires exactly 24 distinct predeclared cases')
    if Counter(c['scenario'] for c in cases) != {'mimikatz':12,'comsvcs':12}:
        raise ValueError('D08 requires 12 cases per scenario')
    rows = [one_case(c,d03_by_line,d07_by_line,d03_flags) for c in cases]
    summary = {
        'total_cases':len(rows),
        'by_expected': dict(sorted(Counter(r['expected'] for r in rows).items())),
        'by_reconstructed': dict(sorted(Counter(r['reconstructed'] for r in rows).items())),
        'agreement':sum(r['agreement'] for r in rows),
        'false_supported':sum(r['false_supported'] for r in rows),
        'false_excluded':sum(r['false_excluded'] for r in rows),
        'source_witness_abstained':sum(r['source_witness_abstained'] for r in rows),
        'source_nonwitness_abstained':sum(r['source_nonwitness_abstained'] for r in rows),
        'binary_false_excluded':sum(r['binary_false_excluded'] for r in rows),
        'membership_counts':dict(sorted(Counter(r['member_count'] for r in rows).items())),
        'matrix':{expected:{found:sum(r['expected']==expected and r['reconstructed']==found for r in rows)
                 for found in ('supported','unsupported','indeterminate')}
                 for expected in ('supported','unsupported','indeterminate')},
    }
    # Do not throw away failed predictions: preserve them as outcomes.
    summary['predeclared_criteria_met'] = (
        summary['agreement']==24 and summary['false_supported']==0 and
        summary['false_excluded']==0 and
        summary['source_witness_abstained']>0 and
        any(r['reconstructed']=='unsupported' and not r['source_witness'] for r in rows)
    )
    return rows,summary


def write_csv(path: Path, rows: list[dict]):
    with path.open('w',encoding='utf8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(cases_path: Path=DEFAULT_CASES, d03_archive: Path=D03_ARCHIVE,
        d03_ref: Path=D03_REF, d07_archive: Path=D07_ARCHIVE,
        d07_preflight: Path=D07_PREFLIGHT, output: Path=DEFAULT_OUT) -> dict:
    locked=json.loads(cases_path.read_text(encoding='utf8'))
    if (locked.get('study')!='D08_predeclared_trivalent_validation' or
            locked.get('policy_window_seconds')!=5):
        raise ValueError('Expected locked D08 case specification, 5s windows')
    # Both sources are SHA-checked against committed D03 and D07 references.
    d03_events,d03_manifest=read_source(d03_archive,d03_ref)
    d03_inventory,_=load_reference(d03_ref)
    flags={r['source_event_id']:r for r in d03_inventory}
    frozen=json.loads(d07_preflight.read_text(encoding='utf8'))
    if frozen.get('study') != 'D07_scenario_preflight':
        raise ValueError('Expected committed D07 preflight report')
    d07_events,_,d07_hashes=read_candidate(d07_archive,frozen)
    d03_by_line={i:ev for i,ev in enumerate(d03_events,1)}
    d07_by_line={ev['line']:ev for ev in d07_events if ev['basis']=='source_UtcTime'}
    rows, summary=evaluate_cases(locked['cases'],d03_by_line,d07_by_line,flags)
    output.mkdir(parents=True,exist_ok=True)
    case_out=output/'d08_case_results.csv'
    summary_out=output/'d08_summary.json'
    manifest_out=output/'d08_manifest.json'
    write_csv(case_out,rows)
    summary_out.write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf8')
    deps=['run_d06_aggregation_representation.py','run_d07_transfer_comparison.py']
    manifest={
        'study':'D08_claim_discrimination',
        'cases_sha256':sha256_file(cases_path),
        'D03_source_archive_sha256':d03_manifest['source_archive_sha256'],
        'D03_inventory_sha256':sha256_file(d03_ref/'d03_source_event_inventory.csv'),
        'D07_source_archive_sha256':d07_hashes['source_archive_sha256'],
        'D07_preflight_sha256':sha256_file(d07_preflight),
        'source_code_sha256':sha256_file(Path(__file__)),
        'locked_decoder_sha256':{d:sha256_file(Path(__file__).with_name(d)) for d in deps},
        'outputs':{'cases_sha256':sha256_file(case_out),'summary_sha256':sha256_file(summary_out)},
        'interpretation':('Predeclared source-field / representation-contract validation; '
             'no independent attack truth, blinded adjudication, operational SOC benefit, '
             'or head-to-head implementation of published forensic-validity methods'),
    }
    manifest_out.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf8')
    return summary


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cases',type=Path,default=DEFAULT_CASES)
    ap.add_argument('--d03-archive',type=Path,default=D03_ARCHIVE)
    ap.add_argument('--d03-ref',type=Path,default=D03_REF)
    ap.add_argument('--d07-archive',type=Path,default=D07_ARCHIVE)
    ap.add_argument('--d07-preflight',type=Path,default=D07_PREFLIGHT)
    ap.add_argument('--output',type=Path,default=DEFAULT_OUT)
    args=ap.parse_args()
    print(json.dumps(run(args.cases,args.d03_archive,args.d03_ref,args.d07_archive,
                         args.d07_preflight,args.output),indent=2))

if __name__=='__main__':
    main()
