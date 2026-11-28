import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.web.evaluation_runs_api import router


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, 'DB', tmp_path/'runs.sqlite3')


def begin(run_id='v1-test'):
    return ledger.start_run(run_id, generation_method='fixture', total=3,
                            code_hashes={'runner': 'a'*64}, model_hashes={'adapter': 'b'*64},
                            data_hashes={'input': 'c'*64})


def test_run_cannot_overwrite_or_invent_progress(database):
    original = begin()
    with pytest.raises(ValueError):
        begin()
    with pytest.raises(ValueError):
        begin(ledger.REPLAY)
    with pytest.raises(ValueError):
        begin('../some_file')
    with pytest.raises(ValueError):
        ledger.update_run('v1-test', completed=2, candidate_count=3)
    for value in (1, 0, -1):
        with pytest.raises(ValueError):
            ledger.update_run('v1-test', completed=value, candidate_count=0, status='completed')
    current = ledger.update_run('v1-test', completed=2, candidate_count=1)
    assert current['code_hashes'] == original['code_hashes']
    assert original['owner_pid'] > 0
    with pytest.raises(ValueError):
        ledger.update_run('v1-test', completed=1, candidate_count=1)
    row = ledger.update_run('v1-test', completed=2, candidate_count=1, status='partial', error='stopped')
    assert ledger.update_run('v1-test', completed=2, candidate_count=1, status='partial', error='stopped') == row
    with pytest.raises(ValueError):
        ledger.update_run('v1-test', completed=3, candidate_count=3, status='completed')


def test_report_and_public_run_use_identical_snapshot(database):
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    begin()
    ledger.update_run('v1-test', completed=3, candidate_count=3, status='completed')
    path = '/api/item4/evaluation-runs/v1-test'
    row = client.get(path).json()
    report = client.get(path+'/report')
    assert report.json() == row == ledger.get_run('v1-test')
    assert row['candidate_count'] == 3 and row['expert_reviewed_count'] == row['prediction_count'] == 0
    assert 'attachment' in report.headers['content-disposition']
    assert client.get(path+'-absent').status_code == 404
    assert client.get('/api/item4/evaluation-runs').json()['runs'][0]['run_id'] == row['run_id']


def test_only_one_concurrent_start_succeeds(database):
    def attempt():
        try:
            begin()
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == [False, True]


def test_distinct_hold_reasons_and_failed_generations_have_separate_counts(database):
    held = dict(generation_status='completed', candidate_status='under_investigation',
                reasons=['supplier_evidence_conflicting_or_unresolved', 'uncertain',
                         'supplier_evidence_conflicting_or_unresolved'],
                product_reasons=['conflicting_supplier_statuses', 'conflicting_supplier_statuses'])
    no_source = dict(generation_status='completed', candidate_status='under_investigation', reasons=[])
    failed = dict(generation_status='partial', candidate_status='under_investigation', reasons=['uncertain'],
                  experts=[dict(execution='error', reason_code='provider_exception')]*2)
    counts = ledger.ProgressCounts()
    for case in (held, no_source, failed):
        counts.add(case)
    value = counts.snapshot()
    assert value == dict(generation_statuses={'completed': 2, 'partial': 1},
                         candidate_statuses={'under_investigation': 2},
                         hold_reasons={'supplier_evidence_conflicting_or_unresolved': 1, 'uncertain': 1, 'reason_not_recorded': 1},
                         product_hold_reasons={'conflicting_supplier_statuses': 1},
                         generation_failure_reasons={'provider_exception': 1})
    begin()
    saved = ledger.update_run('v1-test', completed=3, candidate_count=2, progress=value)
    assert saved['progress'] == value
    counts.remove(failed)
    counts.add(dict(generation_status='completed', candidate_status='fixed'))
    summary = counts.snapshot()
    assert summary['generation_failure_reasons'] == {}
    bad = {**summary, 'hold_reasons': {'uncertain': 1}}
    with pytest.raises(ValueError, match='reason counts'):
        ledger.update_run('v1-test', completed=3, candidate_count=3, progress=bad)
    result = dict(summary, candidates_sha256='d'*64)
    saved = ledger.update_run('v1-test', completed=3, candidate_count=3, result=result, status='completed')
    assert saved['progress'] == summary and saved['result'] == result
    with pytest.raises(ValueError, match='uncounted'):
        counts.remove(failed)


def test_resume_validates_identity_and_keeps_progress(database, monkeypatch):
    inputs = dict(generation_method='moe', total=2, code_hashes={'code':'1'*64},
                  model_hashes={'model':'2'*64}, data_hashes={'input':'3'*64})
    ledger.start_run('long', resumable=True, **inputs)
    counts = ledger.ProgressCounts()
    counts.add(dict(generation_status='completed', candidate_status='fixed'))
    ledger.update_run('long', completed=1, candidate_count=1, progress=counts.snapshot())
    with pytest.raises(ValueError, match='frozen'):
        ledger.resume_run('long', **{**inputs, 'total': 3})
    with monkeypatch.context() as m:
        m.setattr(ledger, '_current_owner', lambda row: False)
        with pytest.raises(ValueError, match='owns'):
            ledger.resume_run('long', **inputs)
        with pytest.raises(ValueError, match='owns'):
            ledger.update_run('long', completed=1, candidate_count=1, status='failed')
        m.setattr(ledger, '_owner_alive', lambda row: False)
        assert ledger.get_run('long')['status'] == 'partial'
        resumed = ledger.resume_run('long', **inputs)
    assert resumed['status'] == 'running' and resumed['resume_count'] == 1
    assert resumed['progress'] == counts.snapshot() and resumed['completed'] == 1
    counts.add(dict(generation_status='completed', candidate_status='under_investigation', reasons=['missing_source']))
    ledger.update_run('long', completed=2, candidate_count=2, status='completed',
                      result=dict(counts.snapshot(), candidates_sha256='4'*64))
    with pytest.raises(ValueError, match='cannot be resumed'):
        ledger.resume_run('long', **inputs)


def test_outcome_and_fingerprint_commit_with_terminal_status(database):
    begin()
    result = {'candidates_sha256': 'd' * 64, 'generation_statuses': {'completed': 2, 'partial': 1},
              'candidate_statuses': {'not_affected': 1, 'under_investigation': 1}}
    update = dict(completed=3, candidate_count=2, status='partial')
    with pytest.raises(ValueError):
        ledger.update_run('v1-test', **update, result={**result, 'generation_statuses': {'completed': 3}})
    assert ledger.get_run('v1-test')['status'] == 'running'
    saved = ledger.update_run('v1-test', **update, result=result)
    assert saved['result'] == ledger.get_run('v1-test')['result'] == result
    assert ledger.update_run('v1-test', **update) == saved
    with pytest.raises(ValueError):
        ledger.update_run('v1-test', **update, result={**result, 'candidates_sha256': 'e' * 64})


def test_owner_loss_records_partial_checkpoint(database, monkeypatch):
    begin()
    ledger.update_run('v1-test', completed=1, candidate_count=1)
    def gone(_pid):
        raise ledger.psutil.NoSuchProcess(_pid)
    monkeypatch.setattr(ledger.psutil, 'Process', gone)
    row = ledger.get_run('v1-test')
    assert row['status'] == 'partial' and row['completed'] == 1
    assert ledger.list_runs()[0]['status'] == 'partial'


def test_archived_reports_are_sourced_from_separate_receipts():
    if not all((ledger.RESULTS / name).is_dir() for name in ledger.ARCHIVES):
        pytest.skip('Historical run receipts are not installed')
    early, previous, replay = (ledger.get_run(k) for k in (ledger.EARLY, ledger.V3, ledger.REPLAY))
    assert early['status'] == 'failed' and early['completed'] is None
    for row in previous, replay:
        assert row['completed'] == row['total'] == row['candidate_count'] == row['prediction_count'] == 97553
        assert row['candidate_origin'] == 'frozen_reference' and row['expert_reviewed_count'] == 0
        assert all(row[k] for k in ('code_hashes', 'model_hashes', 'data_hashes', 'receipt_hashes'))
    assert replay['receipt_hashes'][f'{ledger.REPLAY}/report.json'] == json.loads(
        (ledger.RESULTS/ledger.REPLAY/'independent_verification.json').read_bytes())['verified_report_sha256']
