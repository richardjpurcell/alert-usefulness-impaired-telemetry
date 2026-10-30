"""D06.2: comparison of declared, label-blind telemetry representations.

Reference labels are used exclusively by the evaluator. Policy encoders use raw
Sysmon fields; decoders accept serialized policy rows only. No compromise truth
or operational SOC alert usefulness is estimated.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from build_d03_source_evidence_inventory import basename, normalized_host, source_event_time, sha256_file
from run_d04_evidence_preservation import load_reference, event_seconds

DEFAULT_ARCHIVE = Path('data/raw/mordor/empire_mimikatz_logonpasswords.zip')
DEFAULT_REF = Path('outputs/d03_source_evidence')
DEFAULT_OUT = Path('outputs/d06_aggregation_representation')
WINDOWS = (5, 10, 30)
DEADLINES = (5, 10, 30, 180)
POLICIES = ('P1_count', 'P2_joint', 'P3_pid')
CLAIMS = ('A', 'B', 'C')
SCENARIO = {'host': 'workstation5', 'agent_pid': '1648'}  # Evaluator/decoder only


def compact_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def to_jsonl(rows: list[dict[str, Any]]) -> bytes:
    return ''.join(compact_json(row) + '\n' for row in rows).encode('utf-8')


def utc_iso(sec: float) -> str:
    return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def as_event_id(rec: dict[str, Any]) -> str:
    value = rec.get('EventID')
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return 'missing'


def normalize_pid(pid: Any) -> str:
    return str(pid if pid is not None else '').strip()


def read_source(archive: Path, ref_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify frozen D03 output, raw archive/member and *each* exact source row."""
    inventory, manifest = load_reference(ref_dir)
    if sha256_file(archive) != manifest['source_archive_sha256']:
        raise ValueError('Raw source archive SHA-256 differs from D03 manifest')
    events = []
    with ZipFile(archive) as zf:
        with zf.open(manifest['archive_member']) as raw:
            original = raw.read()
    if hashlib.sha256(original).hexdigest() != manifest['archive_member_sha256']:
        raise ValueError('Raw archive member checksum differs from D03 manifest')
    lines = original.splitlines(keepends=True)
    if len(lines) != len(inventory):
        raise ValueError('Raw record count differs from fixed D03 inventory')
    for pos, (line, fixed) in enumerate(zip(lines, inventory), 1):
        uid = f'mordor_empire_mimikatz:{pos:06d}'
        if (fixed['source_event_id'] != uid or int(fixed['source_line']) != pos
                or hashlib.sha256(line.rstrip(b'\r\n')).hexdigest() != fixed['record_sha256']):
            raise ValueError(f'Raw record identity/hash mismatch at line {pos}')
        record = json.loads(line)
        stamp, basis = source_event_time(record)
        if stamp != fixed['event_time_utc'] or basis != fixed['event_time_basis']:
            raise ValueError(f'Raw event time mismatch at line {pos}')
        if normalized_host(record.get('Hostname')) != normalized_host(fixed['host']):
            raise ValueError(f'Raw host mismatch at line {pos}')
        events.append({'uid': uid, 'record': record, 'host': normalized_host(record.get('Hostname')),
                       'time': event_seconds(stamp), 'basis': basis})
    return events, manifest


def group_events(events: list[dict[str, Any]], window: int) -> list[dict[str, Any]]:
    if window < 1:
        raise ValueError('Window must be positive')
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        grouped[(ev['host'], math.floor(ev['time'] / window))].append(ev)
    return [{'host': host, 'bucket': bucket, 'window': window, 'members': members}
            for (host, bucket), members in sorted(grouped.items())]


def encode_group(group: dict[str, Any], policy: str) -> dict[str, Any]:
    """Pure encoder: never sees D03 labels, source IDs or scenario selector."""
    if policy not in POLICIES:
        raise ValueError(f'Unknown policy {policy}')
    window = group['window']
    row = {'policy': policy, 'host': group['host'],
           'start': utc_iso(group['bucket'] * window),
           'end': utc_iso((group['bucket']+1) * window),
           'count': len(group['members'])}
    if policy == 'P1_count':
        return row
    hist = Counter(as_event_id(m['record']) for m in group['members'])
    row['event_histogram'] = [[k, hist[k]] for k in sorted(hist)]
    tuples: Counter[tuple[str, ...]] = Counter()
    for member in group['members']:
        rec = member['record']
        if as_event_id(rec) != '10':
            continue
        sig = ('10', basename(rec.get('SourceImage')), basename(rec.get('TargetImage')))
        if policy == 'P3_pid':
            sig += (normalize_pid(rec.get('SourceProcessId')),)
        tuples[sig] += 1
    row['process_access'] = [list(sig) + [multiplicity] for sig, multiplicity in sorted(tuples.items())]
    if policy == 'P3_pid':
        # Explicit source timestamp range for the whole group; no source IDs.
        source_times = [m['time'] for m in group['members'] if m['basis'] == 'source_UtcTime']
        row['source_utc_range'] = ([utc_iso(min(source_times)), utc_iso(max(source_times))]
                                   if source_times else None)
    return row


def encode_raw(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Full event records and stable source ID. Not an optimized raw transport format.
    return [{'source_event_id': ev['uid'], 'event_time_utc': utc_iso(ev['time']),
             'event_time_basis': ev['basis'], 'record': ev['record']} for ev in events]


def _triplet(a: bool | None, b: bool | None, c: bool | None) -> dict[str, str]:
    def label(value):
        return 'supported' if value is True else 'unsupported' if value is False else 'indeterminate'
    # A nested claim cannot be false if its more specific claim is supported.
    if c is True and (b is not True or a is not True):
        raise AssertionError('C must imply B and A')
    if b is True and a is not True:
        raise AssertionError('B must imply A')
    return dict(zip(CLAIMS, map(label, (a, b, c))))


def decode_row(serialized_row: bytes, scenario: dict[str, str] = SCENARIO) -> dict[str, str]:
    """Decoder receives bytes only: no raw records, D03 flags or hidden members."""
    row = json.loads(serialized_row)
    policy = row.get('policy')
    if policy == 'P1_count':
        return _triplet(None, None, None)
    if policy not in ('P2_joint', 'P3_pid'):
        raise ValueError('Unknown encoded aggregate policy')
    hist = dict(row['event_histogram'])
    tuples = row['process_access']
    if sum(int(v) for v in hist.values()) != row['count']:
        raise ValueError('Event histogram inconsistent with aggregate size')
    if sum(int(t[-1]) for t in tuples) != int(hist.get('10', 0)):
        raise ValueError('Process-access tuples incomplete')
    all_structured = all(len(t) == (5 if policy == 'P3_pid' else 4) and int(t[-1]) >= 1
                         and t[1] and t[2] for t in tuples)
    # Missing images might obscure a match, producing indeterminate, not absent.
    a_hits = [t for t in tuples if t[0] == '10' and t[2] == 'lsass.exe']
    b_hits = [t for t in a_hits if t[1] == 'powershell.exe']
    a = True if a_hits else (False if all_structured else None)
    b = True if b_hits else (False if all_structured else None)
    if not b_hits:
        c = False if all_structured else None
    elif policy == 'P2_joint':
        c = None  # PID discarded; cannot verify the documented agent.
    elif row['host'] != scenario['host']:
        c = False
    else:
        c_hits = [t for t in b_hits if t[3] == str(scenario['agent_pid'])]
        c = True if c_hits else (False if all(t[3] for t in b_hits) else None)
    return _triplet(a, b, c)


def decode_raw_row(row_bytes: bytes, scenario: dict[str, str] = SCENARIO) -> dict[str, str]:
    raw = json.loads(row_bytes)
    rec = raw['record']
    eid = as_event_id(rec)
    if eid != '10':
        return _triplet(False, False, False)
    target, source = basename(rec.get('TargetImage')), basename(rec.get('SourceImage'))
    if not target:
        return _triplet(None, None, None)
    a = target == 'lsass.exe'
    if not a:
        return _triplet(False, False, False)
    if not source:
        return _triplet(True, None, None)
    b = source == 'powershell.exe'
    if not b:
        return _triplet(True, False, False)
    if normalized_host(rec.get('Hostname')) != scenario['host']:
        return _triplet(True, True, False)
    pid = normalize_pid(rec.get('SourceProcessId'))
    c = pid == str(scenario['agent_pid']) if pid else None
    return _triplet(True, True, c)


def oracle_flags(members: list[dict[str, Any]], flags: dict[str, dict[str, str]]) -> dict[str, bool]:
    # Evaluator-only oracle; not available to any encoding/decoding routine.
    return {'A': any(flags[m['uid']]['lsass_access'] == '1' for m in members),
            'B': any(flags[m['uid']]['powershell_lsass_access'] == '1' for m in members),
            'C': any(flags[m['uid']]['documented_agent_lsass_access'] == '1' for m in members)}


def build_rows(events: list[dict[str, Any]], inventory: list[dict[str, str]],
               windows: tuple[int, ...] = WINDOWS) -> tuple[dict[str, bytes], list[dict[str, Any]], list[dict[str, Any]]]:
    fixed_flags = {r['source_event_id']: r for r in inventory}
    files: dict[str, bytes] = {}
    summaries: list[dict[str, Any]] = []
    reconstruction: list[dict[str, Any]] = []
    event_by_id = {ev['uid']: ev for ev in events}
    raw = encode_raw(events)
    raw_bytes = to_jsonl(raw)
    files['P0_raw.jsonl'] = raw_bytes
    raw_lines = raw_bytes.splitlines()
    raw_results = [decode_raw_row(line) for line in raw_lines]
    for i, ev in enumerate(events):
        truth = oracle_flags([ev], fixed_flags)
        if any((raw_results[i][claim] == 'supported') != truth[claim] for claim in CLAIMS):
            raise ValueError(f'P0 raw reconstruction differs from frozen D03 oracle: {ev["uid"]}')
    base = {'policy': 'P0_raw', 'window_seconds': 0, 'units': len(raw),
            'source_records': len(events), 'unit_reduction_ratio': 1.0,
            'json_bytes': len(raw_bytes), 'gzip_bytes': len(gzip.compress(raw_bytes, mtime=0)),
            'true_source_utc_records': sum(e['basis']=='source_UtcTime' for e in events),
            'index_fallback_records': sum(e['basis']=='index_timestamp_fallback' for e in events),
            'false_supported': 0, 'false_excluded': 0, 'indeterminate_claims': 0,
            'A_supported': 4, 'B_supported': 1, 'C_supported': 1,
            'A_event_id_recovered': 4, 'B_event_id_recovered': 1, 'C_event_id_recovered': 1}
    summaries.append(base)
    for window in windows:
        groups = group_events(events, window)
        for policy in POLICIES:
            encoded = [encode_group(group, policy) for group in groups]
            data = to_jsonl(encoded)
            files[f'{policy}_{window}s.jsonl'] = data
            # Decoder uses serialized bytes only; no internal groups passed in.
            decoded = [decode_row(line) for line in data.splitlines()]
            counts = Counter()
            first_time: dict[str, float] = {}
            initial_source_time: dict[str, float] = {}
            buffering_delay = []
            raw_basis = Counter()
            for idx, (group, outcome) in enumerate(zip(groups, decoded)):
                truth = oracle_flags(group['members'], fixed_flags)
                emission = (group['bucket'] + 1) * window
                for ev in group['members']:
                    raw_basis[ev['basis']] += 1
                for claim in CLAIMS:
                    status = outcome[claim]
                    if status == 'supported': counts[f'{claim}_supported'] += 1
                    if status == 'indeterminate': counts['indeterminate_claims'] += 1
                    if status == 'supported' and not truth[claim]: counts['false_supported'] += 1
                    if status == 'unsupported' and truth[claim]: counts['false_excluded'] += 1
                    witnesses = [ev for ev in group['members'] if fixed_flags[ev['uid']][
                        {'A':'lsass_access','B':'powershell_lsass_access','C':'documented_agent_lsass_access'}[claim]] == '1']
                    if witnesses and status == 'supported':
                        first_time[claim] = min(first_time.get(claim, float('inf')), emission)
                        initial_source_time[claim] = min(initial_source_time.get(claim, float('inf')),
                                                       *(ev['time'] for ev in witnesses))
                        for ev in witnesses:
                            buffering_delay.append(emission-ev['time'])
                            for deadline in DEADLINES:
                                if emission-ev['time'] <= deadline:
                                    counts[f'{claim}_timely_{deadline}s_witnesses'] += 1
                    reconstruction.append({'policy': policy, 'window_seconds': window,
                                           'group_index': idx, 'host': group['host'],
                                           'bucket_start': encoded[idx]['start'],
                                           'claim': claim, 'status': status,
                                           'oracle_present': int(truth[claim]),
                                           'true_witness_count': len(witnesses),
                                           'timestamp_source_witnesses': sum(ev['basis']=='source_UtcTime' for ev in witnesses),
                                           'timestamp_fallback_witnesses': sum(ev['basis']=='index_timestamp_fallback' for ev in witnesses),
                                           'emission_utc': utc_iso(emission)})
            if counts['false_supported'] or counts['false_excluded']:
                raise AssertionError(f'Unexpected false claims under policy {policy}: {counts}')
            summaries.append({'policy': policy, 'window_seconds': window, 'units':len(encoded),
                              'source_records':len(events), 'unit_reduction_ratio':round(len(events)/len(encoded),6),
                              'json_bytes': len(data), 'gzip_bytes':len(gzip.compress(data,mtime=0)),
                              'true_source_utc_records':raw_basis['source_UtcTime'],
                              'index_fallback_records':raw_basis['index_timestamp_fallback'],
                              **{k:counts[k] for k in ('false_supported','false_excluded','indeterminate_claims')},
                              **{f'{c}_supported':counts[f'{c}_supported'] for c in CLAIMS},
                              **{f'{c}_event_id_recovered':0 for c in CLAIMS},
                              **{f'{c}_ledger_present':int(c in first_time) for c in CLAIMS},
                              **{f'{c}_first_available_utc':utc_iso(first_time[c]) if c in first_time else '' for c in CLAIMS},
                              **{f'{c}_first_source_utc':utc_iso(initial_source_time[c]) if c in initial_source_time else '' for c in CLAIMS},
                              **{f'{c}_timely_{d}s_witnesses':counts[f'{c}_timely_{d}s_witnesses'] for c in CLAIMS for d in DEADLINES},
                              'buffering_delay_min_s':round(min(buffering_delay),6) if buffering_delay else '',
                              'buffering_delay_max_s':round(max(buffering_delay),6) if buffering_delay else ''})
    return files, summaries, reconstruction


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def run(archive: Path = DEFAULT_ARCHIVE, ref_dir: Path = DEFAULT_REF,
        out_dir: Path = DEFAULT_OUT) -> dict[str, Any]:
    events, ref_manifest = read_source(archive, ref_dir)
    with (ref_dir/'d03_source_event_inventory.csv').open(newline='', encoding='utf-8') as stream:
        inventory = list(csv.DictReader(stream))
    files, summaries, reconstruction = build_rows(events, inventory)
    # Timestamp-basis diagnostic only: exclude index-time-fallback records,
    # not a substitute for the full-source comparison. All four reference
    # evidence records have actual Sysmon source UTC times.
    source_time_events = [ev for ev in events if ev['basis'] == 'source_UtcTime']
    _, source_time_summaries, _ = build_rows(source_time_events, inventory)
    sensitivity_rows = []
    for full, subset in zip(summaries, source_time_summaries):
        if (full['policy'],full['window_seconds']) != (subset['policy'],subset['window_seconds']):
            raise AssertionError('Timestamp-basis sensitivity misalignment')
        sensitivity_rows.append({
            'policy':full['policy'], 'window_seconds':full['window_seconds'],
            'all_records':len(events), 'source_utc_only_records':len(source_time_events),
            'all_units':full['units'], 'source_utc_only_units':subset['units'],
            **{f'{claim}_all_supported_groups':full[f'{claim}_supported'] for claim in CLAIMS},
            **{f'{claim}_source_utc_only_supported_groups':subset[f'{claim}_supported'] for claim in CLAIMS},
            **{f'{claim}_source_utc_only_ledger_present':subset.get(f'{claim}_ledger_present','') for claim in CLAIMS},
        })
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = out_dir/'policy_outputs'
    payload.mkdir(parents=True, exist_ok=True)
    for filename, data in files.items():
        (payload/filename).write_bytes(data)
    summary_file = out_dir/'d06_policy_summary.csv'
    detail_file = out_dir/'d06_claim_reconstruction.csv'
    write_csv(summary_file, summaries)
    write_csv(detail_file, reconstruction)
    sensitivity_file = out_dir/'d06_source_time_sensitivity.csv'
    write_csv(sensitivity_file, sensitivity_rows)
    manifest = {
        'experiment': 'D06_aggregation_representation_comparison',
        'baseline': 'D03 immutable source evidence; no host-compromise ground truth',
        'reference': {'D03_manifest_sha256':sha256_file(ref_dir/'d03_evidence_manifest.json'),
                      'source_archive_sha256':ref_manifest['source_archive_sha256'],
                      'inventory_sha256':ref_manifest['outputs']['inventory_sha256'],
                      'evidence_sha256':ref_manifest['outputs']['evidence_sha256']},
        'design': {'windows_seconds':list(WINDOWS), 'deadlines_seconds':list(DEADLINES),
                   'policies':['P0_raw',*POLICIES], 'scenario_documentation_association':SCENARIO,
                   'grouping':'normalized host, UTC-aligned tumbling window',
                   'emission':'bucket end (synthetic zero transport delay)',
                   'bytes':'canonical sorted UTF-8 JSONL and deterministic gzip (mtime 0)',
                   'raw_bytes_note':'P0 includes full raw JSON plus source IDs and D03 time metadata',
                   'provenance':'P1/P2/P3 do not expose original source-event IDs',
                   'P3_time_range':'source_UtcTime min/max where available; fallback not re-labelled',
                   'policy_eligibility':'all EventID=10 process-access events, no LSASS filtering',
                   'claim_C':'scenario host/PID association used by decoder only'},
        'outputs': {'summary_sha256':sha256_file(summary_file), 'reconstruction_sha256':sha256_file(detail_file),
                    'source_time_sensitivity_sha256':sha256_file(sensitivity_file),
                    'policy_files_sha256':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())}},
        'observations': {'source_events':len(events), 'process_access_records':sum(as_event_id(ev['record'])=='10' for ev in events),
                         'source_utc_only_records':len(source_time_events),
                         'policy_files':len(files), 'summary_rows':len(summaries),
                         'claim_rows':len(reconstruction), 'source_time_sensitivity_rows':len(sensitivity_rows)},
        'limitations': ['Candidate representations are specified by experimenters, not commercial aggregator implementations.',
                        'Successful claim recovery is conditional on retained defining fields and must not be called detection accuracy.',
                        'D03 record labels remain an evaluation oracle, not incident truth.',
                        'Source-time fallback for 5347 of 6026 events may affect grouping and buffering interpretations.',
                        'The serialized size is a byte-count proxy, not observed infrastructure resource use.',
                        'No event identity recovery is credited to P1/P2/P3 without explicit source IDs.']}
    manifest_file = out_dir/'d06_experiment_manifest.json'
    manifest_file.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return {'observations':manifest['observations'], 'summary_sha256':manifest['outputs']['summary_sha256'],
            'claim_reconstruction_sha256':manifest['outputs']['reconstruction_sha256']}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,default=DEFAULT_ARCHIVE)
    parser.add_argument('--reference',type=Path,default=DEFAULT_REF)
    parser.add_argument('--output',type=Path,default=DEFAULT_OUT)
    args=parser.parse_args()
    print(json.dumps(run(args.archive,args.reference,args.output),indent=2))

if __name__=='__main__':
    main()
