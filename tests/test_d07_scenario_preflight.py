"""Structural fixture tests; no actual D07 dataset is required to run these."""
import importlib.util
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/run_d07_scenario_preflight.py'
spec = importlib.util.spec_from_file_location('d07_preflight', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture_zip(tmp_path, name='example.zip', member='source.json', records=None):
    path = tmp_path / name
    if records is None:
        records = [
            {'EventID': 10, 'Hostname': 'a', 'UtcTime': '2020-01-01 01:00:00',
             'SourceImage': r'C:\\a.exe', 'TargetImage': r'C:\\b.exe', 'SourceProcessId': '22'},
            {'EventID': '1', 'Hostname': 'b', '@timestamp': '2020-01-01T00:00:00Z',
             'Image': r'C:\\b.exe', 'CommandLine': 'benign args'},
            {'EventID': None, 'Hostname': 'b'},
        ]
    with ZipFile(path, 'w') as zf:
        zf.writestr(member, ''.join(json.dumps(row) + '\n' for row in records))
    return path


def test_structural_counts_and_time_basis(tmp_path):
    path = fixture_zip(tmp_path)
    result = module.inspect_zip(path)
    assert result['records'] == 3
    assert result['event_id_counts'] == {'1': 1, '10': 1, 'unknown': 1}
    assert result['timestamp_basis_counts'] == {'index_timestamp_fallback': 1, 'source_UtcTime': 1, 'unknown': 1}
    assert result['event10_field_coverage']['with_joint_images'] == 1
    assert result['event1_field_coverage']['with_image_and_command_line'] == 1
    assert result['scope'] == 'structure_only_no_attack_labels'


def test_repeated_preflight_is_byte_identical(tmp_path):
    archive = fixture_zip(tmp_path)
    one, two = module.inspect_zip(archive), module.inspect_zip(archive)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_unknown_and_string_event_types():
    assert module.event_type('10') == '10'
    assert module.event_type(None) == 'unknown'
    assert module.event_type('not_an_int') == 'unknown'


def test_ambiguous_members_require_explicit_choice(tmp_path):
    archive = tmp_path / 'two.zip'
    with ZipFile(archive, 'w') as zf:
        zf.writestr('a.json', '{}\n')
        zf.writestr('b.json', '{}\n')
    with pytest.raises(ValueError, match='pass --member'):
        module.inspect_zip(archive)
    assert module.inspect_zip(archive, member='b.json')['source_member'] == 'b.json'


def test_invalid_json_is_rejected(tmp_path):
    archive = tmp_path / 'bad.zip'
    with ZipFile(archive, 'w') as zf:
        zf.writestr('events.json', '{not-json}\n')
    with pytest.raises(ValueError, match='Invalid JSON at source line 1'):
        module.inspect_zip(archive)


def test_non_dict_is_rejected(tmp_path):
    archive = tmp_path / 'bad.zip'
    with ZipFile(archive, 'w') as zf:
        zf.writestr('events.json', '[1,2,3]\n')
    with pytest.raises(ValueError, match='Non-object JSON'):
        module.inspect_zip(archive)


def test_invalid_zip_is_rejected(tmp_path):
    bad = tmp_path / 'bad.zip'
    bad.write_bytes(b'not a zip')
    with pytest.raises(ValueError, match='Invalid ZIP'):
        module.inspect_zip(bad)


def test_empty_member_is_rejected(tmp_path):
    archive = tmp_path / 'empty.zip'
    with ZipFile(archive, 'w') as zf:
        zf.writestr('events.json', '')
    with pytest.raises(ValueError, match='No source JSONL'):
        module.inspect_zip(archive)


def test_source_field_coverage_without_signatures(tmp_path):
    archive = fixture_zip(tmp_path)
    result = module.inspect_zip(archive)
    dumped = json.dumps(result)
    assert 'lsass.exe' not in dumped
    assert 'documented_agent' not in dumped
    assert 'compromised' not in dumped
