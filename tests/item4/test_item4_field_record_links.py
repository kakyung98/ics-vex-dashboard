import json
import sqlite3

from tools.item4 import audit_item4_field_record_links as field


def seed_store(path, rows=(), table='objects'):
    with sqlite3.connect(path) as db:
        db.execute(f'CREATE TABLE {table}(kind TEXT, id TEXT, payload TEXT)')
        db.executemany(f'INSERT INTO {table} VALUES(?,?,?)', rows)


def test_exact_matches_empty_replay_and_private_data(tmp_path):
    case = 'OX3-' + 'd' * 28
    packet = 'a' * 64
    bom = {'bomFormat': 'CycloneDX', 'metadata': {'component': {'name': 'example-private-asset'}}}
    idx = {'case_id': {case}, 'input_row_sha256': {'b' * 64}, 'packet_sha256': {packet},
           'bom_sha256': {field.semantic_sha(bom)}}
    rows = [
        ('item4_questionnaire', {'input_bom': bom}),
        ('item4_questionnaire', {'input_bom': bom, 'context_answers': {'deployment': 'running'}}),
        ('item4_questionnaire', {'input_bom': bom, 'new_evidence_column': 'case documentation'}),
        ('operational-context-v1', {'packet': {'synthetic': True}, 'cve': 'CVE-1234-5678'}),
        ('site-private-id', {'note': 'record link SHA256:' + packet, 'id': case}),
    ]
    path = tmp_path / 'objects.sqlite3'
    seed_store(path, [(kind, 'private-row-id', json.dumps(doc)) for kind, doc in rows])
    original = path.read_bytes()
    result = field.examine_store(path, 'objects', idx)
    assert result['records_examined'] == 5
    assert result['exact_reference_records'] == 4
    assert result['synthetic_bom_only_records'] == 1
    assert result['manual_review_records'] == 3
    assert result['matching_records_by_reference'] == dict(case_id=1, input_row_sha256=0, packet_sha256=1, bom_sha256=3)
    assert result['by_kind']['other'] == result['operating_context_origins']['synthetic_packet'] == 1
    out = json.dumps(result)
    assert all(word not in out for word in ['example-private-asset', 'private-row-id', 'site-private-id', packet, case])
    assert path.read_bytes() == original


def test_unavailable_sources_and_stores_are_not_zero_links(tmp_path, monkeypatch):
    missing = field.audit(delivery=tmp_path / 'missing', runtime=tmp_path)
    assert missing['frozen_source']['status'] == 'not_examined' and missing['verified_field_record_links'] is None
    idx = dict.fromkeys(field.INDEX_KEYS, frozenset())
    monkeypatch.setattr(field, 'frozen_index', lambda _: (idx, {'status': 'complete'}))
    result = field.audit(delivery=tmp_path, runtime=tmp_path)
    assert result['status'] == 'incomplete' and result['records_examined'] is None
    assert all(row == {'status': 'not_examined', 'reason': 'store_missing'} for row in result['stores'].values())
    assert not list(tmp_path.iterdir())


def test_attached_cases_require_review_and_active_journals_are_skipped(tmp_path, monkeypatch):
    tag = 'OX3-' + 'c' * 28
    idx = {key: {tag} if key == 'case_id' else set() for key in field.INDEX_KEYS}
    monkeypatch.setattr(field, 'frozen_index', lambda _: (idx, {'status': 'complete'}))
    for name, table in field.STORE_DEFS.values():
        rows = [('job', 'example', json.dumps({'note': 'attached: ' + tag}))] if table == 'objects' else []
        seed_store(tmp_path / name, rows, table)
    result = field.audit(delivery=tmp_path, runtime=tmp_path)
    assert result['status'] == 'requires_manual_review'
    assert result['manual_review_records'] == 1 and result['verified_field_record_links'] is None
    (tmp_path / 'identification_jobs_active.sqlite3-wal').write_bytes(b'uncheckpointed')
    skipped = field.audit(delivery=tmp_path, runtime=tmp_path)
    assert skipped['stores']['job_objects']['reason'] == 'uncheckpointed_or_active_journal'
    assert skipped['status'] == 'incomplete' and skipped['verified_field_record_links'] is None
