import hashlib
import io
import json
import sqlite3
import zlib

import pytest

from tools.item4 import verify_item4_scenario_run as audit


def test_v1_subset_requires_the_complete_hash_bound_export():
    cve, other = 'CVE-2099-0001', 'CVE-2099-0002'
    expected = {'one':(cve,''), 'two':(other,'')}
    selected = {cve}
    rows = [dict(id=i, cve=scope[0], run_id='moe-test') for i, scope in expected.items()]
    def read(values, sha=None):
        raw = b''.join(json.dumps(row).encode() + b'\n' for row in values)
        return list(audit.cohort_rows(io.BytesIO(raw), 'moe-test', expected, selected,
                                      sha or hashlib.sha256(raw).hexdigest()))
    assert read(rows) == [rows[0]]
    with pytest.raises(ValueError, match='missing scenarios'):
        read(rows[:1])
    with pytest.raises(ValueError, match='duplicate'):
        read(rows + [rows[1]])
    with pytest.raises(ValueError, match='identity'):
        read([rows[0], {**rows[1], 'cve': cve}])
    with pytest.raises(ValueError, match='sealed result'):
        read(rows, '0'*64)


@pytest.fixture
def retry_db():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE candidates(id,cve,packet_sha,generation,attempts,row_sha,payload)')
    db.execute('CREATE TABLE prior_attempts(id,attempt,row_sha,payload)')
    for identifier, attempts in [('one', ['failed','partial','completed']), ('two', ['partial','partial']),
                                 ('three',['completed'])]:
        for i, generation in enumerate(attempts, 1):
            row = dict(run_id='moe-test', id=identifier, cve='fixture-cve', version='v2',
                       packet_sha256='a'*64, input_sha256='b'*64, generation_status=generation,
                       candidate_status='fixed' if generation == 'completed' else 'under_investigation')
            raw = json.dumps(row).encode()
            seal = (hashlib.sha256(raw).hexdigest(), zlib.compress(raw))
            if i == len(attempts):
                db.execute('INSERT INTO candidates VALUES (?,?,?,?,?,?,?)',
                           (identifier, row['cve'], row['packet_sha256'], generation, i, *seal))
            else:
                db.execute('INSERT INTO prior_attempts VALUES (?,?,?,?)', (identifier, i, *seal))
    try:
        yield db
    finally:
        db.close()


def test_retry_history_counts_unique_cases_once(retry_db):
    assert audit.retry_history(retry_db, 'moe-test') == dict(unique_retried_scenarios=2, superseded_attempts=3,
        recovered_to_completed=1, still_partial=1, still_failed=0, candidate_statuses={'fixed':1})


@pytest.mark.parametrize('corruption', [
    "UPDATE prior_attempts SET attempt=4 WHERE attempt=2",
    "UPDATE prior_attempts SET row_sha='bad' WHERE attempt=2",
    "UPDATE prior_attempts SET id='two' WHERE attempt=2",
    "UPDATE candidates SET row_sha='bad' WHERE id='one'",
    "UPDATE candidates SET generation='failed' WHERE id='one'",
    "UPDATE candidates SET attempts=2 WHERE id='one'",
    "DELETE FROM candidates WHERE id='one'",
])
def test_retry_history_rejects_corruption(retry_db, corruption):
    retry_db.execute(corruption)
    with pytest.raises(ValueError):
        audit.retry_history(retry_db, 'moe-test')


def test_checkpoint_recounts_final_reasons_and_checks_pinned_rows(tmp_path):
    rid = 'moe-fixture'
    cve = 'CVE-2099-0001'
    packet_sha = 'c' * 64
    record = dict(run_id=rid, total=3, generation_method='fixture', code_hashes={},
                  model_hashes={}, data_hashes={})
    expected = {k: (cve, 'unknown') for k in ('one', 'two', 'three')}
    manifest = {f'{audit.runs.PREFIX}/cves/{cve}.json': packet_sha}
    path = tmp_path / 'records.sqlite3'
    wire = 'd' * 64
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE metadata(run_id,pins)')
        db.execute('INSERT INTO metadata VALUES (?,?)', (rid, json.dumps(record)))
        db.execute('CREATE TABLE experts(wire_sha,value)')
        db.execute('INSERT INTO experts VALUES (?,?)',
                   (wire, json.dumps(dict(llm_used=True, model='fixture', prediction={}))))
        db.execute('CREATE TABLE candidates(ordinal,id,cve,packet_sha,generation,row_sha,payload)')
        for i, identifier in enumerate(('one','two')):
            experts = [dict(expert=role, execution='model', llm_used=True, model_called=True,
                            verdict='unresolved', wire_sha256=wire)
                       for role in ('inventory','crosscheck')]
            generation = 'completed' if i == 0 else 'failed'
            if i:
                for e in experts:
                    e.update(execution='error', reason_code='provider_exception')
            row = dict(id=identifier, run_id=rid, cve=cve, packet_sha256=packet_sha, synthetic=True,
                       expert_validated=False, verified_product={'state':'unknown'}, generation_status=generation,
                       candidate_status='under_investigation', reasons=['unknown', 'unknown', 'absent_source'],
                       product_reasons=[], routed_experts=['inventory','crosscheck'], experts=experts)
            raw = json.dumps(row).encode()
            db.execute('INSERT INTO candidates VALUES (?,?,?,?,?,?,?)',
                       (i, identifier, cve, packet_sha, generation, hashlib.sha256(raw).hexdigest(), zlib.compress(raw)))
            with (tmp_path/'candidates.jsonl').open('ab') as out:
                out.write(raw + b'\n')
    def read():
        return audit.audit_rows(audit.checkpoint_rows(path, record, expected), expected, manifest, rid)
    result = read()
    assert result['generation_statuses'] == {'failed': 1, 'completed': 1}
    assert result['candidate_statuses'] == {'under_investigation': 1}
    assert result['hold_reasons'] == {'unknown': 1, 'absent_source': 1}
    assert result['generation_failure_reasons'] == {'provider_exception': 1}
    assert result['missing_scenarios'] == 1
    exported = list(audit.exported_rows(tmp_path, record, [cve], expected, 1))
    assert audit.audit_rows(exported, expected, manifest, rid) == result
    with sqlite3.connect(path) as db:
        db.execute('DELETE FROM experts')
    with pytest.raises(ValueError, match='no recorded model response'):
        list(audit.exported_rows(tmp_path, record, [cve], expected, 0))
    with sqlite3.connect(path) as db:
        db.execute('UPDATE candidates SET ordinal=2 WHERE id="one"')
    with pytest.raises(ValueError, match='ordinal'):
        read()
    with sqlite3.connect(path) as db:
        db.execute('UPDATE candidates SET ordinal=0, row_sha="bad" WHERE id="one"')
    with pytest.raises(ValueError, match='fingerprint'):
        read()
    with pytest.raises(ValueError, match='metadata'):
        list(audit.checkpoint_rows(path, {**record, 'total': 2}, expected))
