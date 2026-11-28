from contextlib import closing
import json
import sqlite3

import pytest

from src.item4.evaluation import bulk_scenario_runner as bulk; from src.item4.evaluation import scenario_evaluation_runner as runs


def test_bulk_retries_incomplete_rows_and_recovers_from_interrupted_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(runs.ledger, 'DB', tmp_path / 'ledger.sqlite3')
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path / 'results')
    monkeypatch.setattr(runs, 'scoped_inputs', lambda _: (dict(component_ref='ref', version='1'), None))
    cve = 'CVE-2099-1000'
    key = f'{runs.PREFIX}/cves/{cve}.json'
    path = tmp_path / key
    path.parent.mkdir(parents=True)
    cases = [dict(id=id, cve=cve, answers={}, context={}, synthetic=True, actual_affected=True)
             for id in ('A','B','C')]
    path.write_bytes(bulk.encoded(dict(cve=cve, cases=cases, ground_truth='held-out')))
    plan = (tmp_path, {key: runs.file_sha(path)}, [cve], 'all')
    pins = {'selected case IDs': runs.sha(bulk.encoded(['A','B','C']))}
    args = dict(generation_method='scenario_moe_local_llm', total=3, code_hashes=pins,
                model_hashes=pins, data_hashes=pins)
    record = runs.ledger.start_run('bulk-fixture', resumable=True, **args)
    seen = []
    interrupted = True
    cachekey = (0, 'a' * 64)
    receipt = {'model': 'test-double', 'prediction': {'finding': 'unknown'}}

    def fixture(items, *, cache, batch_size):
        scenario, _, _ = items[0]
        assert set(scenario) == {'id','cve','answers','context','synthetic','component_ref','version'}
        case = scenario['id']
        seen.append(case)
        if case == 'A':
            cache[cachekey] = receipt
        else:
            assert cache[cachekey] == receipt
        if case == 'C' and interrupted:
            raise ConnectionError('fixture worker disconnected')
        failed = case == 'B' and interrupted
        return [dict(id=case, cve=cve, generation_status='partial' if failed else 'completed',
                     candidate_status='under_investigation', reasons=['unclear', 'unclear'],
                     synthetic=True, expert_validated=False,
                     experts=[dict(execution='error',reason_code='invalid_output') if failed else dict(execution='model')])]

    row = bulk.execute(record, plan, generator=fixture, chunk_size=1)
    assert (row['status'],row['completed'],row['candidate_count']) == ('partial',2,1)
    assert row['result']['generation_failure_reasons'] == {'invalid_output':1}
    interrupted = False
    record = runs.ledger.resume_run('bulk-fixture', **args)
    row = bulk.execute(record, plan, generator=fixture, chunk_size=1, resume=True)
    assert (row['status'],row['completed'],row['candidate_count']) == ('completed',3,3)
    assert seen == ['A','B','C','B','C']
    assert row['result']['generation_failure_reasons'] == {}
    assert row['result']['hold_reasons'] == {'unclear':3}
    folder = runs.OUTPUT / row['run_id']
    assert runs.file_sha(folder/'candidates.jsonl') == row['result']['candidates_sha256']
    assert [json.loads(v)['id'] for v in (folder/'candidates.jsonl').read_bytes().splitlines()] == ['A','B','C']
    assert json.loads((folder/'report.json').read_bytes())['ledger'] == row
    with closing(sqlite3.connect(folder/'records.sqlite3')) as db:
        assert db.execute('SELECT id,attempt FROM prior_attempts').fetchall() == [('B',1)]
        db.execute("UPDATE experts SET value='bad' WHERE wire_sha=?", (cachekey[1],))
        db.execute('UPDATE experts SET value=cast(value as BLOB)')
        with pytest.raises(ValueError, match='fingerprint'):
            bulk.ExpertCache(db)[cachekey]
