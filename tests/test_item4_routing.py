import json
from pathlib import Path
from copy import deepcopy
import pytest
from fastapi.testclient import TestClient
from src.cwe_taxonomy import load, ancestry
from src.vex_routing import classify
from src import item4_review as I4, vex_roles as VR
from src.item4_questions import validate
from src.operational_questions import _validate_questions


def case(cwe='CWE-787', description='An out-of-bounds write affects packet processing.', cve='CVE-2099-12345'):
    return {'cve': cve, 'cwe': [cwe], 'description': description}


def test_official_pinned_taxonomy_and_multiple_ancestry():
    t = load()
    assert len(t['records']) >= 984
    assert len([r for r in t['records'].values() if r['abstraction'] == 'Pillar']) == 10
    a = ancestry('CWE-787')
    assert 'CWE-119' in a['ancestors'] and a['pillars'] and not a['errors']
    custom = {'version': 'test', 'records': {
        'X': {'parents_view_1000': ['A', 'B']},
        'A': {'abstraction': 'Pillar'}, 'B': {'abstraction': 'Pillar'}}}
    assert set(ancestry('X', custom)['pillars']) == {'A', 'B'}
    custom['records']['X']['parents_view_1000'].append('X')
    assert 'ancestry_cycle' in ancestry('X', custom)['errors']


@pytest.mark.parametrize('cwe', ['CWE-120', 'CWE-787', 'CWE-416', 'CWE-362'])
def test_required_source_never_uses_operational_fallback(cwe, monkeypatch):
    calls = []
    monkeypatch.setattr(VR, 'infer', lambda *a: calls.append(a))
    result = I4.start([case(cwe)])
    row = result['statements'][0]
    assert row['status'] == 'under_investigation'
    assert row['analysis_route']['route'] == 'defer_missing_source'
    assert row['extraction']['status'] == row['authoring']['status'] == 'not_run'
    with pytest.raises(ValueError): I4.questions(result['review_id'])
    assert not calls
    assert classify(case(cwe), source_available=True)['route'] == 'source_analysis'


def test_operational_requires_specific_CWE_and_evidence():
    op = case('CWE-319', 'Sensitive information is sent in cleartext over the device network.')
    assert classify(op)['requirement'] == 'operational_review'
    # A detailed observable transport weakness is enough to choose a review,
    # never enough to decide a VEX status. Broad parent CWE-200 still needs context.
    assert classify(case('CWE-319', 'A product vulnerability exists.'))['requirement'] == 'operational_review'
    assert classify(case('CWE-200', 'A product vulnerability exists.'))['requirement'] == 'undetermined'
    assert classify(case('CWE-284', 'Authentication requirements are unspecified.'))['requirement'] == 'undetermined'
    assert classify(case('CWE-999999'))['requirement'] == 'undetermined'
    assert classify({'cve': op['cve'], 'description': op['description']})['requirement'] == 'undetermined'
    op['cwe'].append('CWE-787')
    assert classify(op)['requirement'] == 'source_required'
    op['cwe'] = ['CWE-319', 'CWE-999999']
    assert classify(op)['requirement'] == 'undetermined'
    op['cwe'] = ['CWE-319'];op['description'] += ' A buffer overflow also occurs.'
    assert classify(op)['requirement'] == 'source_required'


def test_new_questions_require_both_scopes_and_operator_facts():
    sources = [{'id': 'E1', 'text': 'Network traffic is unencrypted.', 'source': {}}]
    rows = [{'scope': scope, 'question': question, 'purpose': 'Review transport configuration.',
             'evidence_ids': ['E1']} for scope, question in [
                 ('common', 'On this asset, which network protocols are configured?'),
                 ('specific', 'On this asset, is the documented device interface in use?')]]
    output = {'prediction': {'questions': rows}}
    assert validate(output, sources, {}, _validate_questions)[0]
    original_question=rows[1]['question']
    rows[1]['question'] += ' (Evidence ID: E1'
    checked=validate(output, sources, {}, _validate_questions)
    assert checked[0] and checked[1][1]['question']==original_question
    assert checked[3][0]['change']=='trailing_duplicate_source_annotation_removed'
    assert rows[1]['question'].endswith('E1')  # original output retained
    rows[1]['question']=original_question
    rows[1]['scope'] = 'common'
    assert not validate(output, sources, {}, _validate_questions)[0]
    rows[1]['scope'] = 'specific';rows[1]['question'] = 'On this asset, is the function reachable in the CFG?'
    assert not validate(output, sources, {}, _validate_questions)[0]
    rows[1]['question'] = 'On this asset, which interface is used? E1'
    assert 'source_ids_must_not_appear_in_question_text' in validate(output, sources, {}, _validate_questions)[2]


def test_mixed_reviews_preserve_source_and_blocked_results(monkeypatch):
    blocked = case()
    op = case('CWE-319', 'Network traffic is unencrypted.', 'CVE-2099-12346')
    result = I4.start([blocked, op])
    rid = result['review_id']
    captured = []
    def create(cases, *a, **kw):
        captured.extend(cases)
        assert kw['question_role'] == 'item4-questions'
        return {'id': 'plan', 'cases': []}
    monkeypatch.setattr(I4.OQ, 'create', create)
    I4.questions(rid)
    assert [c['cve'] for c in captured] == [op['cve']]
    source_statement = {**result['statements'][0], 'arm': 'source-code', 'status': 'not_affected'}
    I4.record_source(rid, {'statements': [source_statement]})
    operational_statement = deepcopy(result['statements'][1]);operational_statement['reason'] = 'Operator review retained.'
    monkeypatch.setattr(I4.OQ, 'assess', lambda *a, **kw: {'statements': [operational_statement]})
    combined = I4.answers(rid, {})
    assert [s['status'] for s in combined['statements']] == ['not_affected', 'under_investigation']
    assert combined['routes'][blocked['cve']]['route'] == 'source_analysis'
    with pytest.raises(ValueError): I4.record_source(rid, {'statements': [operational_statement]})


def test_api_no_source_route_and_foreign_answer_rejection(monkeypatch):
    from src.api_server import app
    calls = []
    monkeypatch.setattr(VR, 'infer', lambda *a: calls.append(a))
    client = TestClient(app)
    start = client.post('/api/item4/start', json={'cves': [case()]} )
    assert start.status_code == 200, start.text
    rid = start.json()['review_id']
    assert client.post('/api/item4/' + rid + '/questions').status_code == 400
    assert client.post('/api/item4/' + rid + '/answers', json={'plan_id': 'foreign', 'answers': {}}).status_code == 400
    assert client.get('/api/item4/reviews/' + rid).status_code == 200
    assert not calls


@pytest.mark.parametrize('first_attempt_truncated', [False, True])
def test_operator_pipeline_new_role_and_original_sbom_keep_blocked_case(monkeypatch, first_attempt_truncated):
    from tests.test_shared_vex_pipeline import provider
    calls = []; original = provider(calls)
    def infer(role, packet):
        if role == 'item4-questions':
            calls.append((role, deepcopy(packet)))
            if first_attempt_truncated and sum(r == role for r, _ in calls) == 1:
                return {'prediction': None, 'raw': '{"questions":[', 'error': 'output_token_limit'}
            return {'prediction': {'questions': [
                {'scope': scope, 'question': q, 'purpose': 'Review protocol configuration.',
                 'evidence_ids': [packet['sources'][0]['id']]}
                for scope, q in [('common', 'On this asset, which transport protocols are configured?'),
                                  ('specific', 'On this asset, is the documented device network interface in use?')]]}}
        if role == 'operation-assessment':
            return {'prediction': {'assessment': 'likely_cannot_determine', 'explanation': 'Records are incomplete.',
                                  'answer_refs': [packet['questions_and_answers'][0]['id']], 'missing_evidence': []}}
        return original(role, packet)
    monkeypatch.setattr(VR, 'infer', infer)
    blocked = case(); op = case('CWE-319', 'Network traffic is unencrypted.', 'CVE-2099-12346')
    for c in [blocked, op]: c['mappings'] = [{'component_id': 'device'}]
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'components': [{'type': 'firmware', 'name': 'Fixture device', 'bom-ref': 'device'}]}
    initial = I4.start([blocked, op], sbom=sbom)
    plan = I4.questions(initial['review_id'])
    assert plan['cases'][0]['generation']['status'] == 'validated'
    assert len(plan['cases'][0]['generation']['attempts']) == 1
    assert {q['scope'] for q in plan['cases'][0]['questions'] if q['origin'] == 'rule'} == {'common', 'specific'}
    final = I4.answers(initial['review_id'], {})
    assert len(final['sbom_vex']['vulnerabilities']) == 2
    assert all(v['analysis']['state'] == 'in_triage' for v in final['sbom_vex']['vulnerabilities'])
    assert final['statements'][0]['extraction']['status'] == 'not_run'
    assert final['sbom_vex_validation']['status'] == 'valid'
    assert 'vulnerabilities' not in sbom


def test_source_api_uses_locked_CWE_group_not_client_replacements(monkeypatch):
    import io, zipfile
    from tests.test_shared_vex_pipeline import provider
    from src.api_server import app
    calls = [];monkeypatch.setattr(VR, 'infer', provider(calls))
    client = TestClient(app)
    required = case(description='The parse_frame function processes malformed frames with an out-of-bounds write.')
    op = case('CWE-319', 'Network traffic is unencrypted.', 'CVE-2099-12346')
    started = client.post('/api/item4/start', json={'cves': [required, op]}).json()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('main.c', 'int parse_frame(int n){return n;} int main(void){return parse_frame(3);}\n')
        z.writestr('compile_commands.json', json.dumps([{'file': 'main.c', 'arguments': ['cc', '-c', 'main.c']}]))
    uploaded = client.post('/api/source/upload', files={'file': ('source.zip', archive.getvalue(), 'application/zip')}).json()
    payload = {'session': uploaded['session'], 'item4_review_id': started['review_id'],
               'analysis_scope': 'product', 'entry_points': ['main'], 'tree_is_complete': True}
    invalid = client.post('/api/source/judge', json={**payload, 'cves': [op]})
    assert invalid.status_code == 400
    # Client tries to replace the authoritative required weakness with an operational one.
    response = client.post('/api/source/judge', json={**payload, 'cves': [{'cve': required['cve'], 'cwe': ['CWE-319'], 'description': 'cleartext'}]})
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result['statements']) == 2
    assert result['routes'][required['cve']]['requirement'] == 'source_required'
    assert result['routes'][required['cve']]['route'] == 'source_analysis'
    assert result['statements'][1]['extraction']['status'] == 'not_run'
    assert all(p.get('cve', p.get('vulnerability')) != op['cve'] for _, p in calls)


def test_v3_dataset_is_group_bound_pending_and_role_scoped():
    root = Path(__file__).resolve().parents[1]
    path = root / 'data/item4_v3'
    manifest = json.loads((path / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['independent_gold_count'] == manifest['train_ready_count'] == 0
    groups = {}
    for split, n in [('train', 800), ('validation', 100), ('test', 100)]:
        rows = [json.loads(l) for l in (path / (split + '.cases.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert len(rows) == n and all(r['routing_gold'] is None for r in rows)
        groups[split] = {r['group_id'] for r in rows}
        requirements = {r['cve']: r['analysis_route_prediction']['requirement'] for r in rows}
        questions = [json.loads(l) for l in (path / (split + '.questions.annotation.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert all(requirements[r['cve']] == 'operational_review' and not r['train_ready'] for r in questions)
        scenarios = [json.loads(l) for l in (path / (split + '.scenarios.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert all(s['split'] == split and s['group_id'] in groups[split] and s['reference_status'] is None for s in scenarios)
    assert not groups['train'] & groups['test'] and not groups['train'] & groups['validation']
    import hashlib
    for name, expected in manifest['source_input_hashes'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
