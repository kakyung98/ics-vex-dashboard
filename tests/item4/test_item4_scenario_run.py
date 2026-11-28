import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.web import scenario_evaluation_api as api
from src.item4.web.evaluation_runs_api import router as ledger_router


@pytest.mark.parametrize('method', [
    'scenario_moe_local_llm', 'scenario_moe_h200_llm', 'scenario_moe_supplier_review_pilot',
    'scenario_moe_explicit_inventory_review',
])
def test_runner_keeps_partial_attempts_blind_and_protects_download(tmp_path, monkeypatch, method):
    monkeypatch.setattr(runs.ledger, 'DB', tmp_path / 'runs.sqlite3')
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path / 'output')
    cve = 'CVE-2099-1001'
    key = f'{runs.PREFIX}/cves/{cve}.json'
    p = tmp_path / key
    p.parent.mkdir(parents=True)
    cases = [dict(id=str(i), cve=cve, context={}, answers={}, synthetic=True, actual_affected=True)
             for i in range(2)]
    p.write_text(json.dumps(dict(cve=cve, cases=cases, ground_truth='held-out')), encoding='utf-8')
    pins = {'fixture': runs.file_sha(p)}
    record = runs.ledger.start_run('fixture', generation_method=method, total=2,
                                   code_hashes=pins, model_hashes=pins, data_hashes=pins)
    monkeypatch.setattr(runs, 'scoped_inputs', lambda _: (dict(component_ref='component', version='1'), None))

    def candidate(inputs, product, **kwargs):
        assert set(inputs) == {'id', 'cve', 'answers', 'context', 'synthetic', 'component_ref', 'version'}
        return dict(id=inputs['id'], generation_status='completed' if inputs['id'] == '0' else 'failed',
                    candidate_status='under_investigation', experts=[], expert_validated=False)

    monkeypatch.setattr(runs.candidate_policy, 'generate_candidate', candidate)
    row = runs.execute_run(record, (tmp_path, {key: pins['fixture']}, [cve], 'v1'))
    assert (row['status'], row['completed'], row['candidate_count'], row['expert_reviewed_count']) == ('partial', 2, 1, 0)
    output = runs.OUTPUT / 'fixture'
    assert json.loads((output / 'report.json').read_bytes())['ledger'] == row
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    url = '/api/item4/evaluation-runs/fixture/candidates'
    head = client.head(url)
    assert head.status_code == 200 and not head.content
    assert int(head.headers['content-length']) == (output / 'candidates.jsonl').stat().st_size
    assert len(client.get(url).content.splitlines()) == 2
    with (output / 'candidates.jsonl').open('a', encoding='utf-8') as stream:
        stream.write('{}\n')
    assert client.get(url).status_code == 409
    assert client.head(url).status_code == 409
    with pytest.raises(ValueError, match='fingerprint'):
        runs.input_packet(tmp_path, {key: '0' * 64}, cve)


def test_rule_requires_exact_component_cve_quote_and_document():
    cve, key = 'CVE-2099-1111', 'supplier:asset'
    quote = 'Service enabled'
    ref = dict(source_id='source', span=[0, len(quote)], quote=quote)
    src = dict(id='source', text=quote, text_sha256=runs.sha(quote.encode()), document_sha256='d', product_keys=[key])
    scenario = dict(product_keys=[key], conditions=[dict(id='atom', operator_observable=True, source_ref=ref)],
                    expression={'condition': 'atom'})
    detail = dict(cve=cve, sources=[src], scenarios=[scenario])
    row = dict(evidence_id='eid', status='known_affected', version_membership='true', product_key=key,
               document_sha256='d', source_ids=['source'])
    product = dict(state='known_affected', component_ref='a', evidence=[row])
    question = dict(id='q1', component_ref='a', cve=cve, operational_quote=quote, source_refs=[ref])
    result = runs.condition_rule(detail, [question], product)
    assert result['conditions'][0]['evidence_id'] == 'eid'
    assert runs.condition_rule(detail, [dict(question, component_ref='b')], product) is None
    assert runs.condition_rule(detail, [dict(question, cve='CVE-2099-9999')], product) is None
    assert runs.condition_rule(detail, [dict(question, operational_quote='Other')], product) is None
    assert runs.condition_rule(detail, [question], dict(product, evidence=[dict(row, document_sha256='other')])) is None
    assert runs.condition_rule(dict(detail, scenarios=[scenario, scenario]), [question], product) is None
    other = dict(scenario, conditions=[dict(id='other', operator_observable=False, source_ref=ref)])
    assert runs.condition_rule(dict(detail, scenarios=[other, scenario]), [question], product) == result


def test_inventory_report_serves_only_sealed_review_files(tmp_path, monkeypatch):
    monkeypatch.setattr(runs.ledger, 'DB', tmp_path / 'runs.sqlite3')
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path)
    folder = tmp_path / 'fixture'
    folder.mkdir()
    files = {'report.ko.html': b'<html lang="ko"></html>', 'report.json': b'{}',
             'independent_verification.json': b'{}', 'prior_not_affected_review.jsonl': b'{}\n'}
    candidates = folder / 'candidates.jsonl'
    candidates.write_bytes(b'{}\n')
    for name, content in files.items():
        (folder / name).write_bytes(content)
    hashes = {name: runs.file_sha(folder / name) for name in files}
    runs.ledger.start_run('fixture', generation_method='scenario_moe_explicit_inventory_review', total=1,
                          code_hashes={'rule': 'a' * 64}, model_hashes={'model': 'b' * 64}, data_hashes=hashes)
    app = FastAPI()
    app.include_router(api.router)
    app.include_router(ledger_router)
    client = TestClient(app)
    url = '/api/item4/evaluation-runs/fixture/inventory-review/'
    assert client.get(url + 'report.ko.html').status_code == 404
    review = dict(previous_candidate_statuses={'not_affected': 1}, transitions={'not_affected': {'under_investigation': 1}},
                  prior_not_affected_review=dict(reviewed=1, retained=0, changed_to_under_investigation=1,
                                                 coverage_values={'<missing>': 1}, source_runs={'prior': 1}),
                  absence_evidence_review=dict(reviewed=1, explicit_complete=0, partial=0, missing=1, other=0,
                                               already_under_investigation=0, prior_crosscheck_holds_replaced=0),
                  additional_model_calls=0)
    closing = dict(completed=1, candidate_count=1, status='completed',
                   result={'candidates_sha256': runs.file_sha(candidates), 'generation_statuses': {'completed': 1},
                           'candidate_statuses': {'under_investigation': 1}})
    with pytest.raises(ValueError, match='transitions differ'):
        runs.ledger.update_run('fixture', **closing, inventory_review=dict(review, transitions={}))
    saved = runs.ledger.update_run('fixture', **closing, inventory_review=review)
    assert saved['inventory_review'] == client.get('/api/item4/evaluation-runs/fixture/report').json()['inventory_review'] == review
    for name, content in {**files, 'candidates.jsonl': candidates.read_bytes()}.items():
        response = client.get(url + name)
        assert response.status_code == 200 and response.content == content
        assert client.head(url + name).status_code == 200
        (folder / name).write_bytes(b'modified')
        assert client.get(url + name).status_code == 409
    assert client.get(url + 'unsealed.json').status_code == 404
