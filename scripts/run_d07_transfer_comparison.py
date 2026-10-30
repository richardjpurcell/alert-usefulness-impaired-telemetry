"""D07.2: locked D06 P0–P3 representation transfer to OTRF Comsvcs scenario.

The D06 encoder and group mechanics are imported, never reimplemented.
Raw evidence tests are reference-only; decoders receive serialized bytes only.
Unknown-time records are inventoried but excluded from windowed comparisons.
No host-compromise or operational utility inference is made.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from build_d03_source_evidence_inventory import basename, normalized_host, source_event_time, sha256_file
from run_d04_evidence_preservation import event_seconds
from run_d06_aggregation_representation import (
    WINDOWS, DEADLINES, POLICIES, as_event_id, group_events, encode_group,
    encode_raw, to_jsonl, utc_iso, compact_json,
)
from run_d07_scenario_preflight import inspect_zip

DEFAULT_ARCHIVE = Path('data/raw/mordor/psh_lsass_memory_dump_comsvcs.zip')
DEFAULT_PREFLIGHT = Path('outputs/d07_scenario_preflight/d07_source_structure.json')
DEFAULT_OUTPUT = Path('outputs/d07_transfer_comparison')
CLAIMS = ('T1', 'T2', 'T3')


def oracle_claims(rec: dict) -> dict[str, bool]:
    """Reference-only source-field query, never passed into the D06 encoder."""
    eid = as_event_id(rec)
    t1 = eid == '10' and basename(rec.get('TargetImage')) == 'lsass.exe'
    t2 = t1 and basename(rec.get('SourceImage')) == 'rundll32.exe'
    cmd = str(rec.get('CommandLine') or '').casefold()
    t3 = eid == '1' and basename(rec.get('Image')) == 'rundll32.exe' and (
        'comsvcs.dll' in cmd and 'minidump' in cmd)
    return {'T1': t1, 'T2': t2, 'T3': t3}


def read_candidate(archive: Path, frozen: dict) -> tuple[list[dict], list[dict], dict]:
    """Verify source against D07.1, establish immutable source-line/hash reference."""
    if sha256_file(archive) != frozen['source_archive_sha256']:
        raise ValueError('D07 ZIP checksum differs from committed preflight')
    with ZipFile(archive) as zf:
        raw = zf.read(frozen['source_member'])
    if hashlib.sha256(raw).hexdigest() != frozen['source_member_sha256']:
        raise ValueError('D07 JSON member checksum differs from preflight')
    all_rows, eligible = [], []
    for i, line in enumerate(raw.splitlines(), 1):
        rec = json.loads(line)
        if not isinstance(rec, dict):
            raise ValueError(f'Non-object record {i}')
        time_string, basis = source_event_time(rec)
        item = {
            'uid':f'd07_comsvcs:{i:06d}', 'line':i,
            'record_sha256':hashlib.sha256(line.rstrip(b'\r\n')).hexdigest(),
            'host':normalized_host(rec.get('Hostname')),
            'basis':basis, 'event_time_utc':time_string,
            'record':rec,
        }
        all_rows.append(item)
        if basis == 'source_UtcTime':
            eligible.append({**item, 'time':event_seconds(time_string)})
    if len(all_rows) != frozen['records']:
        raise ValueError('Source count changed from preflight')
    actual = Counter(item['basis'] for item in all_rows)
    if dict(actual) != frozen['timestamp_basis_counts']:
        raise ValueError('Timestamp basis changed from preflight')
    return all_rows, eligible, {'source_archive_sha256':frozen['source_archive_sha256'],
                                 'source_member_sha256':frozen['source_member_sha256']}


def _statuses(t1: bool | None, t2: bool | None, t3: bool | None) -> dict[str,str]:
    if t2 is True and t1 is not True:
        raise ValueError('T2 requires T1')
    return {claim:('supported' if val is True else 'unsupported' if val is False else 'indeterminate')
            for claim,val in zip(CLAIMS,(t1,t2,t3))}


def decode_transfer(serialized: bytes) -> dict[str,str]:
    """Query-only decoder; no raw-source reference or precomputed oracle labels."""
    row = json.loads(serialized)
    policy = row.get('policy')
    if policy == 'P1_count':
        return _statuses(None,None,None)
    if policy not in ('P2_joint','P3_pid'):
        raise ValueError('Unexpected policy')
    hist = {str(k):int(v) for k,v in row['event_histogram']}
    if sum(hist.values()) != row['count']:
        raise ValueError('Malformed aggregate histogram')
    tuples = row['process_access']
    sig_length = 5 if policy == 'P3_pid' else 4
    if (any(len(t) != sig_length or t[0] != '10' or int(t[-1]) < 1 for t in tuples)
            or sum(int(t[-1]) for t in tuples) != hist.get('10',0)):
        raise ValueError('Malformed process-access tuples')
    good = all(bool(t[1]) and bool(t[2]) for t in tuples)
    matches_t1 = [t for t in tuples if t[2] == 'lsass.exe']
    matches_t2 = [t for t in matches_t1 if t[1] == 'rundll32.exe']
    t1 = True if matches_t1 else (False if good else None)
    t2 = True if matches_t2 else (False if good else None)
    # P2/P3 only retain histogram for EventID 1: cannot inspect command line.
    t3 = None if hist.get('1',0) else False
    return _statuses(t1,t2,t3)


def decode_raw_transfer(serialized: bytes) -> dict[str,str]:
    row = json.loads(serialized)
    rec = row['record']
    eid = as_event_id(rec)
    if eid == '10':
        target = basename(rec.get('TargetImage'))
        if not target:
            return _statuses(None,None,False)
        if target != 'lsass.exe':
            return _statuses(False,False,False)
        source = basename(rec.get('SourceImage'))
        return _statuses(True, None if not source else source == 'rundll32.exe', False)
    if eid == '1':
        image = basename(rec.get('Image'))
        command = str(rec.get('CommandLine') or '').casefold()
        if not image or not command:
            return _statuses(False,False,None)
        return _statuses(False,False,image=='rundll32.exe' and
                         'comsvcs.dll' in command and 'minidump' in command)
    return _statuses(False,False,False)


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f'No output rows for {path}')
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w',encoding='utf8',newline='') as output:
        writer=csv.DictWriter(output,fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def comparisons(all_rows: list[dict], eligible: list[dict]) -> tuple[dict[str,bytes],list[dict],list[dict],list[dict]]:
    """Compare only truly source-timed records under locked D06 grouping."""
    output_files={}
    summaries=[]
    evaluations=[]
    reference=[]
    for item in all_rows:
        ref = oracle_claims(item['record'])
        reference.append({k:item[k] for k in ('uid','line','record_sha256','host','event_time_utc','basis')}
                         | {'event_id':as_event_id(item['record'])}
                         | {key:int(val) for key,val in ref.items()})
    reference_by_uid = {r['uid']:r for r in reference}
    # Raw comparison: P0 includes all source records; timed P0 subset used for size fairness.
    # D06 encode_raw requires event['time']; untimed raw remains in the audit inventory.
    raw_bytes=to_jsonl(encode_raw(eligible))
    output_files['P0_raw_source_timed.jsonl']=raw_bytes
    for ev,line in zip(eligible,raw_bytes.splitlines()):
        decoded=decode_raw_transfer(line)
        truth=oracle_claims(ev['record'])
        if any((decoded[k]=='supported') != truth[k] for k in CLAIMS):
            raise ValueError(f'P0 raw disagreement at {ev["uid"]}')
    raw_all_bytes=to_jsonl([{'source_event_id':r['uid'], 'event_time_utc':r['event_time_utc'],
                             'event_time_basis':r['basis'], 'record':r['record']} for r in all_rows])
    output_files['P0_full_raw.jsonl']=raw_all_bytes
    raw_claim_counts=Counter()
    for item in all_rows:
        for k,v in oracle_claims(item['record']).items():
            raw_claim_counts[k]+=int(v)
    summaries.append({'policy':'P0_raw','window_seconds':0,'source_records':len(eligible),
                      'total_source_records':len(all_rows), 'excluded_unknown_time':len(all_rows)-len(eligible),
                      'units':len(eligible),'json_bytes':len(raw_bytes),
                      'gzip_bytes':len(gzip.compress(raw_bytes,mtime=0)),
                      'false_supported':0,'false_excluded':0,
                      **{f'{c}_supported_groups':raw_claim_counts[c] for c in CLAIMS},
                      **{f'{c}_ledger_present':int(raw_claim_counts[c]>0) for c in CLAIMS},
                      'T1_source_record_witnesses':raw_claim_counts['T1'],
                      'T2_source_record_witnesses':raw_claim_counts['T2'],
                      'T3_source_record_witnesses':raw_claim_counts['T3']})
    for window in WINDOWS:
        groups=group_events(eligible,window)
        for policy in POLICIES:
            # Existing D06 encode_group is passed the same generic event envelope.
            encoded=[encode_group(group,policy) for group in groups]
            payload=to_jsonl(encoded)
            output_files[f'{policy}_{window}s.jsonl']=payload
            claims=[decode_transfer(line) for line in payload.splitlines()]
            counts=Counter()
            first_emit={}
            for idx,(group,encoded_row,pred) in enumerate(zip(groups,encoded,claims)):
                oracle={k:any(bool(reference_by_uid[m['uid']][k]) for m in group['members']) for k in CLAIMS}
                emit=(group['bucket']+1)*window
                for key in CLAIMS:
                    status=pred[key]
                    counts[f'{key}_{status}']+=1
                    if status=='supported' and not oracle[key]:counts['false_supported']+=1
                    if status=='unsupported' and oracle[key]:counts['false_excluded']+=1
                    witnesses=[m for m in group['members'] if reference_by_uid[m['uid']][key]]
                    if status=='supported' and witnesses:
                        first_emit[key]=min(first_emit.get(key,float('inf')),emit)
                        for m in witnesses:
                            for deadline in DEADLINES:
                                if 0 <= emit-m['time'] <= deadline:
                                    counts[f'{key}_timely_{deadline}s_witnesses']+=1
                    evaluations.append({'policy':policy,'window_seconds':window,
                        'group_index':idx,'host':group['host'], 'bucket_start':encoded_row['start'],
                        'claim':key,'status':status,'oracle_present':int(oracle[key]),
                        'source_witness_count':len(witnesses),
                        'emission_utc':utc_iso(emit)})
            if counts['false_supported'] or counts['false_excluded']:
                raise ValueError(f'Incorrect reconstruction for {policy} {window}s: {counts}')
            summaries.append({'policy':policy,'window_seconds':window,
                'source_records':len(eligible),'total_source_records':len(all_rows),
                'excluded_unknown_time':len(all_rows)-len(eligible),
                'units':len(encoded),'unit_reduction_ratio':round(len(eligible)/len(encoded),6),
                'json_bytes':len(payload),'gzip_bytes':len(gzip.compress(payload,mtime=0)),
                'false_supported':counts['false_supported'],'false_excluded':counts['false_excluded'],
                **{f'{c}_supported_groups':counts[f'{c}_supported'] for c in CLAIMS},
                **{f'{c}_indeterminate_groups':counts[f'{c}_indeterminate'] for c in CLAIMS},
                **{f'{c}_ledger_present':int(c in first_emit) for c in CLAIMS},
                **{f'{c}_first_emission_utc':utc_iso(first_emit[c]) if c in first_emit else '' for c in CLAIMS},
                **{f'{c}_timely_{d}s_witnesses':counts[f'{c}_timely_{d}s_witnesses'] for c in CLAIMS for d in DEADLINES}})
    return output_files,summaries,evaluations,reference


def run(archive: Path=DEFAULT_ARCHIVE, preflight: Path=DEFAULT_PREFLIGHT,
        output: Path=DEFAULT_OUTPUT) -> dict:
    frozen=json.loads(preflight.read_text(encoding='utf8'))
    if frozen['study']!='D07_scenario_preflight':
        raise ValueError('Expected committed D07.1 preflight reference')
    all_rows,eligible,hashes=read_candidate(archive,frozen)
    files,summaries,evaluations,reference=comparisons(all_rows,eligible)
    output.mkdir(parents=True,exist_ok=True)
    pol_dir=output/'policy_outputs'
    pol_dir.mkdir(parents=True,exist_ok=True)
    for name,data in files.items():
        (pol_dir/name).write_bytes(data)
    reference_path=output/'d07_fixed_source_evidence.csv'
    summary_path=output/'d07_transfer_summary.csv'
    reconstruction_path=output/'d07_claim_reconstruction.csv'
    write_csv(reference_path,reference)
    write_csv(summary_path,summaries)
    write_csv(reconstruction_path,evaluations)
    manifest={
        'study':'D07_locked_policy_transfer', 'source':hashes,
        'preflight_sha256':sha256_file(preflight),
        'encoder':'Imported, unchanged D06 encode_group and group_events',
        'encoder_sha256':sha256_file(Path(__file__).with_name('run_d06_aggregation_representation.py')),
        'representation_policies':['P0_raw',*POLICIES],
        'window_seconds':list(WINDOWS), 'deadlines_seconds':list(DEADLINES),
        'time_eligibility':'Only source_UtcTime records can enter UTC-aligned windows; unknown-time records remain separately inventoried',
        'claims':'T1 Event10 LSASS; T2 same Event10 rundll32-to-LSASS; T3 same Event1 rundll32 comsvcs.dll MiniDump invocation',
        'cost_note':'Serialized and gzip bytes are proxies; no observed SOC performance or storage costs',
        'interpretation':'Method transfer and observable event-claim recovery, not independent attack-detection accuracy',
        'limitations':['T3 cannot be established by P2/P3 because they discard EventID 1 command line',
                       'Process correlation via GUID is supported by raw source but is not recoverable from P2/P3',
                       'This is within LSASS credential-access, not broad technique generalization',
                       'Unknown timestamps excluded from windowed comparisons, not fabricated'],
        'observations':{'total_records':len(all_rows),'source_timed_records':len(eligible),
                        'unknown_time_records':len(all_rows)-len(eligible),
                        'source_claims':{c:sum(int(r[c]) for r in reference) for c in CLAIMS},
                        'policy_files':len(files),'summary_rows':len(summaries),
                        'reconstruction_rows':len(evaluations)},
        'outputs':{'reference_sha256':sha256_file(reference_path),
                   'summary_sha256':sha256_file(summary_path),
                   'reconstruction_sha256':sha256_file(reconstruction_path),
                   'policies_sha256':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())}},
    }
    (output/'d07_transfer_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf8')
    return manifest['observations'] | {'summary_sha256':manifest['outputs']['summary_sha256']}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--archive',type=Path,default=DEFAULT_ARCHIVE)
    ap.add_argument('--preflight',type=Path,default=DEFAULT_PREFLIGHT)
    ap.add_argument('--output',type=Path,default=DEFAULT_OUTPUT)
    args=ap.parse_args()
    print(json.dumps(run(args.archive,args.preflight,args.output),indent=2))

if __name__=='__main__':
    main()
