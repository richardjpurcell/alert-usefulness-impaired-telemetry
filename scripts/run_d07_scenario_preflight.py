"""D07 structural preflight for an independent, documented OTRF JSONL archive.

Does not evaluate attack evidence, SOC outcomes, or source-event usefulness.
The predeclared D07 design must be committed before interpreting raw findings.
Standard-library-only; leaves the original source archive unmodified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from zipfile import BadZipFile, ZipFile

DEFAULT_ARCHIVE = Path('data/raw/mordor/psh_lsass_memory_dump_comsvcs.zip')
DEFAULT_OUT = Path('outputs/d07_scenario_preflight/d07_source_structure.json')
DATA_SUFFIXES = ('.json', '.jsonl', '.ndjson')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def select_member(names: list[str], requested: str | None) -> str:
    available = sorted(n for n in names if not n.endswith('/') and
                       not n.startswith('__MACOSX/') and n.lower().endswith(DATA_SUFFIXES))
    if requested:
        if requested not in available:
            raise ValueError(f'Requested JSON member {requested!r} not found; options: {available}')
        return requested
    if len(available) != 1:
        raise ValueError(f'Expected one JSONL member, found {len(available)}: {available}; pass --member')
    return available[0]


def event_type(value: object) -> str:
    try:
        return str(int(value))
    except (TypeError, ValueError, OverflowError):
        return 'unknown'


def not_blank(value: object) -> bool:
    return value is not None and str(value).strip() != ''


def inspect_zip(archive: Path, member: str | None = None) -> dict:
    raw_zip = archive.read_bytes()
    try:
        with ZipFile(archive) as zf:
            selected = select_member(zf.namelist(), member)
            source = zf.read(selected)
    except BadZipFile as e:
        raise ValueError(f'Invalid ZIP archive: {archive}') from e
    counts = Counter()
    hosts = Counter()
    channels = Counter()
    bases = Counter()
    event10 = Counter()
    event1 = Counter()
    for line_no, raw_line in enumerate(source.splitlines(), 1):
        if not raw_line.strip():
            raise ValueError(f'Empty record at source line {line_no}')
        try:
            rec = json.loads(raw_line)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f'Invalid JSON at source line {line_no}') from e
        if not isinstance(rec, dict):
            raise ValueError(f'Non-object JSON at source line {line_no}')
        eid = event_type(rec.get('EventID'))
        counts[eid] += 1
        hosts[str(rec.get('Hostname') or '<missing>')] += 1
        channels[str(rec.get('Channel') or '<missing>')] += 1
        bases['source_UtcTime' if not_blank(rec.get('UtcTime')) else
              'index_timestamp_fallback' if not_blank(rec.get('@timestamp')) else 'unknown'] += 1
        if eid == '10':
            event10['total'] += 1
            if not_blank(rec.get('SourceImage')):
                event10['with_source_image'] += 1
            if not_blank(rec.get('TargetImage')):
                event10['with_target_image'] += 1
            if not_blank(rec.get('SourceProcessId')):
                event10['with_source_pid'] += 1
            if not_blank(rec.get('SourceImage')) and not_blank(rec.get('TargetImage')):
                event10['with_joint_images'] += 1
        elif eid == '1':
            event1['total'] += 1
            if not_blank(rec.get('Image')):
                event1['with_image'] += 1
            if not_blank(rec.get('CommandLine')):
                event1['with_command_line'] += 1
            if not_blank(rec.get('Image')) and not_blank(rec.get('CommandLine')):
                event1['with_image_and_command_line'] += 1
    if not counts:
        raise ValueError('No source JSONL records found')
    return {
        'study': 'D07_scenario_preflight',
        'scope': 'structure_only_no_attack_labels',
        'source_archive_name': archive.name,
        'source_archive_sha256': sha256(raw_zip),
        'source_member': selected,
        'source_member_sha256': sha256(source),
        'records': sum(counts.values()),
        'event_id_counts': dict(sorted(counts.items())),
        'host_counts': dict(sorted(hosts.items())),
        'channel_counts': dict(sorted(channels.items())),
        'timestamp_basis_counts': dict(sorted(bases.items())),
        'event10_field_coverage': dict(sorted(event10.items())),
        'event1_field_coverage': dict(sorted(event1.items())),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--archive', type=Path, default=DEFAULT_ARCHIVE)
    ap.add_argument('--member', default=None, help='Explicit member for archives with multiple JSON files')
    ap.add_argument('--out', type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    result = inspect_zip(args.archive, args.member)
    output = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(output, encoding='utf-8')
    print(output, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
